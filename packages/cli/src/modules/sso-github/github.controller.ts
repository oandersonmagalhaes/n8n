import { Logger } from '@n8n/backend-common';
import { GlobalConfig } from '@n8n/config';
import { Time } from '@n8n/constants';
import { Get, RestController } from '@n8n/decorators';
import { Request, Response } from 'express';

import { AuthService } from '@/auth/auth.service';
import { GITHUB_STATE_COOKIE_NAME } from '@/constants';
import { BadRequestError } from '@/errors/response-errors/bad-request.error';
import { NotFoundError } from '@/errors/response-errors/not-found.error';
import type { AuthlessRequest } from '@/requests';

import { GithubSsoService } from './github.service';

@RestController('/sso/github')
export class GithubSsoController {
	constructor(
		private readonly githubSsoService: GithubSsoService,
		private readonly authService: AuthService,
		private readonly globalConfig: GlobalConfig,
		private readonly logger: Logger,
	) {}

	@Get('/login', { skipAuth: true })
	redirectToGithub(_req: Request, res: Response) {
		if (!this.githubSsoService.isConfigured()) {
			throw new NotFoundError('GitHub SSO is not configured');
		}

		const state = this.githubSsoService.generateState();
		const { samesite, secure } = this.globalConfig.auth.cookie;

		res.cookie(GITHUB_STATE_COOKIE_NAME, state.signed, {
			maxAge: 15 * Time.minutes.toMilliseconds,
			httpOnly: true,
			sameSite: samesite,
			secure,
		});

		res.redirect(this.githubSsoService.buildAuthorizationUrl(state.plaintext));
	}

	@Get('/callback', { skipAuth: true })
	async callbackHandler(req: AuthlessRequest, res: Response) {
		if (!this.githubSsoService.isConfigured()) {
			throw new NotFoundError('GitHub SSO is not configured');
		}

		// Handle errors from GitHub (e.g., user denied access)
		const error = req.query.error;
		if (typeof error === 'string' && error) {
			this.logger.warn('GitHub OAuth2 callback returned an error', { error });
			res.redirect('/?error=github_oauth_denied');
			return;
		}

		const storedState = req.cookies[GITHUB_STATE_COOKIE_NAME];

		if (typeof storedState !== 'string') {
			this.logger.error('GitHub callback: state cookie is missing');
			throw new BadRequestError('Invalid state');
		}

		// Verify stored state JWT
		this.githubSsoService.verifyState(storedState);

		const code = req.query.code;
		if (typeof code !== 'string' || !code) {
			this.logger.error('GitHub callback: code parameter is missing');
			throw new BadRequestError('Authorization code is missing');
		}

		const user = await this.githubSsoService.loginUser(code);

		res.clearCookie(GITHUB_STATE_COOKIE_NAME);
		this.authService.issueCookie(res, user, true, req.browserId);

		res.redirect('/');
	}
}
