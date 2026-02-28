import type { ModuleInterface } from '@n8n/decorators';
import { BackendModule } from '@n8n/decorators';

@BackendModule({ name: 'sso-github', instanceTypes: ['main'] })
export class GithubSsoModule implements ModuleInterface {
	async init() {
		await import('./github.controller');
	}
}
