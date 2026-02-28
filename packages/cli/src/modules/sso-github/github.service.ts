import { Logger } from '@n8n/backend-common';
import { GlobalConfig } from '@n8n/config';
import {
	AuthIdentity,
	AuthIdentityRepository,
	isValidEmail,
	GLOBAL_MEMBER_ROLE,
	type User,
	UserRepository,
} from '@n8n/db';
import { Service } from '@n8n/di';
import { randomBytes, randomUUID } from 'crypto';

import { BadRequestError } from '@/errors/response-errors/bad-request.error';
import { JwtService } from '@/services/jwt.service';
import { UrlService } from '@/services/url.service';

import {
	GITHUB_AUTHORIZATION_URL,
	GITHUB_TOKEN_URL,
	GITHUB_USER_URL,
	GITHUB_EMAILS_URL,
	UUID_REGEX,
} from './constants';

interface GithubUser {
	id: number;
	login: string;
	name: string | null;
	email: string | null;
}

interface GithubEmail {
	email: string;
	primary: boolean;
	verified: boolean;
	visibility: string | null;
}

interface GithubTokenResponse {
	access_token: string;
	token_type: string;
	scope: string;
}

@Service()
export class GithubSsoService {
	constructor(
		private readonly authIdentityRepository: AuthIdentityRepository,
		private readonly urlService: UrlService,
		private readonly globalConfig: GlobalConfig,
		private readonly userRepository: UserRepository,
		private readonly logger: Logger,
		private readonly jwtService: JwtService,
	) {}

	isConfigured(): boolean {
		const { clientId, clientSecret } = this.globalConfig.sso.github;
		return Boolean(clientId && clientSecret);
	}

	getCallbackUrl(): string {
		const restEndpoint = this.globalConfig.endpoints.rest;
		return `${this.urlService.getInstanceBaseUrl()}/${restEndpoint}/sso/github/callback`;
	}

	getLoginUrl(): string {
		const restEndpoint = this.globalConfig.endpoints.rest;
		return `${this.urlService.getInstanceBaseUrl()}/${restEndpoint}/sso/github/login`;
	}

	generateState(): { signed: string; plaintext: string } {
		const state = `n8n_github_state:${randomUUID()}`;
		return {
			signed: this.jwtService.sign({ state }, { expiresIn: '15m' }),
			plaintext: state,
		};
	}

	verifyState(signedState: string): string {
		let state: string;
		try {
			const decoded = this.jwtService.verify(signedState);
			state = decoded?.state;
		} catch (error) {
			this.logger.error('Failed to verify GitHub state', { error });
			throw new BadRequestError('Invalid state');
		}

		if (typeof state !== 'string') {
			throw new BadRequestError('Invalid state');
		}

		const parts = state.split(':');
		if (parts.length !== 2 || parts[0] !== 'n8n_github_state') {
			throw new BadRequestError('Invalid state');
		}

		if (!UUID_REGEX.test(parts[1])) {
			throw new BadRequestError('Invalid state');
		}

		return state;
	}

	buildAuthorizationUrl(state: string): string {
		const { clientId } = this.globalConfig.sso.github;
		const callbackUrl = this.getCallbackUrl();
		const params = new URLSearchParams({
			client_id: clientId,
			redirect_uri: callbackUrl,
			scope: 'user:email',
			state,
		});
		return `${GITHUB_AUTHORIZATION_URL}?${params.toString()}`;
	}

	private async exchangeCodeForToken(code: string): Promise<string> {
		const { clientId, clientSecret } = this.globalConfig.sso.github;
		const callbackUrl = this.getCallbackUrl();

		const response = await fetch(GITHUB_TOKEN_URL, {
			method: 'POST',
			headers: {
				Accept: 'application/json',
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				client_id: clientId,
				client_secret: clientSecret,
				code,
				redirect_uri: callbackUrl,
			}).toString(),
		});

		if (!response.ok) {
			this.logger.error('GitHub token exchange failed', { status: response.status });
			throw new BadRequestError('Failed to exchange authorization code');
		}

		const data = (await response.json()) as GithubTokenResponse;

		if (!data.access_token) {
			this.logger.error('GitHub token response missing access_token');
			throw new BadRequestError('Failed to exchange authorization code');
		}

		return data.access_token;
	}

	private async fetchGithubUser(accessToken: string): Promise<GithubUser> {
		const response = await fetch(GITHUB_USER_URL, {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				Accept: 'application/vnd.github+json',
				'X-GitHub-Api-Version': '2022-11-28',
			},
		});

		if (!response.ok) {
			this.logger.error('Failed to fetch GitHub user', { status: response.status });
			throw new BadRequestError('Failed to fetch user information from GitHub');
		}

		return (await response.json()) as GithubUser;
	}

	private async fetchGithubUserEmails(accessToken: string): Promise<GithubEmail[]> {
		const response = await fetch(GITHUB_EMAILS_URL, {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				Accept: 'application/vnd.github+json',
				'X-GitHub-Api-Version': '2022-11-28',
			},
		});

		if (!response.ok) {
			this.logger.error('Failed to fetch GitHub user emails', { status: response.status });
			return [];
		}

		return (await response.json()) as GithubEmail[];
	}

	private getPrimaryEmail(githubUser: GithubUser, emails: GithubEmail[]): string | null {
		// If the user has a public email on the profile, use it
		if (githubUser.email && isValidEmail(githubUser.email)) {
			return githubUser.email;
		}

		// Otherwise find the verified primary email
		const primary = emails.find((e) => e.primary && e.verified);
		if (primary) return primary.email;

		// Fallback: first verified email
		const verified = emails.find((e) => e.verified);
		if (verified) return verified.email;

		return null;
	}

	async loginUser(code: string): Promise<User> {
		const accessToken = await this.exchangeCodeForToken(code);
		const [githubUser, emails] = await Promise.all([
			this.fetchGithubUser(accessToken),
			this.fetchGithubUserEmails(accessToken),
		]);

		const providerId = String(githubUser.id);

		// Check if we already have this GitHub identity linked to a user
		const existingIdentity = await this.authIdentityRepository.findOne({
			where: { providerId, providerType: 'github' },
			relations: { user: { role: true } },
		});

		if (existingIdentity) {
			return existingIdentity.user;
		}

		const email = this.getPrimaryEmail(githubUser, emails);

		if (!email) {
			throw new BadRequestError(
				'No verified email found in your GitHub account. Please add and verify an email address on GitHub.',
			);
		}

		if (!isValidEmail(email)) {
			throw new BadRequestError('Invalid email format received from GitHub');
		}

		// Check if a user with this email already exists → link the GitHub identity
		const existingUser = await this.userRepository.findOne({
			where: { email },
			relations: ['authIdentities', 'role'],
		});

		if (existingUser) {
			this.logger.debug(
				`GitHub SSO: User with email ${email} already exists, linking GitHub identity.`,
			);
			const identity = this.authIdentityRepository.create({
				providerId,
				providerType: 'github',
				userId: existingUser.id,
			});
			await this.authIdentityRepository.save(identity);
			return existingUser;
		}

		// Create a new user with the GitHub identity
		const nameParts = (githubUser.name ?? githubUser.login).split(' ');
		const firstName = nameParts[0] ?? githubUser.login;
		const lastName = nameParts.slice(1).join(' ') || '';

		// Generate a secure random password - this account uses GitHub SSO so the
		// password field is never used for authentication
		const unusablePassword = randomBytes(32).toString('hex');

		return await this.userRepository.manager.transaction(async (trx) => {
			const { user } = await this.userRepository.createUserWithProject(
				{
					firstName,
					lastName,
					email,
					authIdentities: [],
					role: GLOBAL_MEMBER_ROLE,
					password: unusablePassword,
				},
				trx,
			);

			await trx.save(
				trx.create(AuthIdentity, {
					providerId,
					providerType: 'github',
					userId: user.id,
				}),
			);

			return user;
		});
	}
}
