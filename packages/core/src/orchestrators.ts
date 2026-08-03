export interface UserRequest {
  readonly prompt: string;
  readonly orchestrator?: string;
  readonly cwd: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface OrchestratorContext { readonly request: UserRequest; }
export interface Orchestrator { readonly name: string; matches(request: UserRequest): boolean; run(context: OrchestratorContext): Promise<unknown>; }
