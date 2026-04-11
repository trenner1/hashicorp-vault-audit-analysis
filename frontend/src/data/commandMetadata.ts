// Command metadata for displaying help information in the UI
export interface CommandFlag {
  name: string
  description: string
  type: 'string' | 'int' | 'bool'
  required?: boolean
  default?: string
}

export interface SubcommandMetadata {
  name: string
  description: string
  flags: CommandFlag[]
  example?: string
}

export interface CommandMetadata {
  name: string
  description: string
  category: 'entity' | 'kv' | 'client' | 'system' | 'vault-api'
  requiresFiles: boolean
  requiresVaultAPI: boolean
  subcommands?: SubcommandMetadata[]
  flags?: CommandFlag[]
  example?: string
}

export const COMMAND_METADATA: Record<string, CommandMetadata> = {
  'entity-analysis': {
    name: 'entity-analysis',
    description: 'Analyze entity behavior and lifecycle across audit logs',
    category: 'entity',
    requiresFiles: true,
    requiresVaultAPI: false,
    subcommands: [
      {
        name: 'churn',
        description: 'Track entity login patterns and identify returning vs new entities',
        flags: [
          { name: '--entity-map', description: 'Path to entity mappings JSON file', type: 'string' },
          { name: '--baseline', description: 'Path to baseline entities JSON file', type: 'string' },
          { name: '--output', description: 'Output file path', type: 'string' },
          { name: '--format', description: 'Output format (json or csv)', type: 'string', default: 'json' },
        ],
        example: 'vault-audit entity-analysis churn --entity-map mappings.json --output churn.json audit.log',
      },
      {
        name: 'creation',
        description: 'Identify when entities were first created in the audit logs',
        flags: [
          { name: '--entity-map', description: 'Path to entity mappings JSON file', type: 'string' },
          { name: '--output', description: 'Output file path', type: 'string' },
        ],
        example: 'vault-audit entity-analysis creation --entity-map mappings.json audit.log',
      },
      {
        name: 'preprocess',
        description: 'Build entity ID to display name mappings from audit logs',
        flags: [
          { name: '--output', description: 'Output file path', type: 'string', required: true },
          { name: '--format', description: 'Output format (json or csv)', type: 'string', default: 'json' },
        ],
        example: 'vault-audit entity-analysis preprocess --output mappings.json audit.log',
      },
      {
        name: 'gaps',
        description: 'Detect gaps in entity activity (periods of inactivity)',
        flags: [
          { name: '--window-seconds', description: 'Minimum gap duration in seconds', type: 'int', default: '86400' },
        ],
        example: 'vault-audit entity-analysis gaps --window-seconds 3600 audit.log',
      },
      {
        name: 'timeline',
        description: 'Show chronological activity timeline for a specific entity',
        flags: [
          { name: '--entity-id', description: 'Entity ID to analyze', type: 'string', required: true },
          { name: '--display-name', description: 'Display name for the entity', type: 'string' },
        ],
        example: 'vault-audit entity-analysis timeline --entity-id abc123 audit.log',
      },
    ],
  },
  'kv-analysis': {
    name: 'kv-analysis',
    description: 'Analyze KV secret access patterns and changes',
    category: 'kv',
    requiresFiles: true,
    requiresVaultAPI: false,
    subcommands: [
      {
        name: 'analyze',
        description: 'Analyze KV secret access patterns from audit logs',
        flags: [
          { name: '--kv-prefix', description: 'KV mount path prefix', type: 'string', default: 'secret/' },
          { name: '--output', description: 'Output CSV file path', type: 'string' },
          { name: '--entity-csv', description: 'Entity mappings CSV file', type: 'string' },
        ],
        example: 'vault-audit kv-analysis analyze --kv-prefix secret/ --output kv.csv audit.log',
      },
      {
        name: 'compare',
        description: 'Compare two KV analysis CSV files to identify changes',
        flags: [
          { name: '--csv1', description: 'First CSV file path', type: 'string', required: true },
          { name: '--csv2', description: 'Second CSV file path', type: 'string', required: true },
        ],
        example: 'vault-audit kv-analysis compare --csv1 before.csv --csv2 after.csv',
      },
      {
        name: 'summary',
        description: 'Generate summary statistics from KV analysis CSV',
        flags: [
          { name: '--csv', description: 'Input CSV file path', type: 'string', required: true },
        ],
        example: 'vault-audit kv-analysis summary --csv kv.csv',
      },
    ],
  },
  'client-traffic-analysis': {
    name: 'client-traffic-analysis',
    description: 'Analyze client IP traffic patterns, errors, and behavior',
    category: 'client',
    requiresFiles: true,
    requiresVaultAPI: false,
    flags: [
      { name: '--output', description: 'Output file path', type: 'string' },
      { name: '--format', description: 'Output format (json or csv)', type: 'string', default: 'csv' },
      { name: '--error-details-output', description: 'Separate file for detailed error instances', type: 'string' },
      { name: '--top', description: 'Number of top clients to show', type: 'int', default: '20' },
      { name: '--temporal', description: 'Show hourly activity distribution', type: 'bool' },
      { name: '--min-requests', description: 'Minimum requests to include client', type: 'int', default: '10' },
      { name: '--show-operations', description: 'Show operation breakdown', type: 'bool' },
      { name: '--show-errors', description: 'Show error analysis', type: 'bool' },
      { name: '--show-details', description: 'Show detailed client analysis', type: 'bool' },
    ],
    example: 'vault-audit client-traffic-analysis --top 50 --show-errors --output clients.csv audit.log',
  },
  'token-analysis': {
    name: 'token-analysis',
    description: 'Analyze token usage patterns and detect potential abuse',
    category: 'client',
    requiresFiles: true,
    requiresVaultAPI: false,
    flags: [
      { name: '--min-operations', description: 'Minimum operations to include token', type: 'int', default: '100' },
      { name: '--abuse-threshold', description: 'Threshold for abuse detection', type: 'int', default: '10000' },
      { name: '--operation-filter', description: 'Filter by operation types (comma-separated)', type: 'string' },
    ],
    example: 'vault-audit token-analysis --min-operations 50 --abuse-threshold 5000 audit.log',
  },
  'path-hotspots': {
    name: 'path-hotspots',
    description: 'Identify most frequently accessed Vault paths',
    category: 'system',
    requiresFiles: true,
    requiresVaultAPI: false,
    flags: [
      { name: '--top', description: 'Number of top paths to show', type: 'int', default: '20' },
    ],
    example: 'vault-audit path-hotspots --top 50 audit.log',
  },
  'system-overview': {
    name: 'system-overview',
    description: 'Generate comprehensive system-wide usage statistics',
    category: 'system',
    requiresFiles: true,
    requiresVaultAPI: false,
    flags: [
      { name: '--top', description: 'Number of top items to show per category', type: 'int', default: '10' },
      { name: '--min-ops', description: 'Minimum operations to include', type: 'int', default: '10' },
      { name: '--namespace-filter', description: 'Filter by namespace', type: 'string' },
      { name: '--sequential', description: 'Process files sequentially', type: 'bool' },
    ],
    example: 'vault-audit system-overview --top 20 --min-ops 5 audit.log',
  },
  'k8s-auth': {
    name: 'k8s-auth',
    description: 'Analyze Kubernetes authentication patterns',
    category: 'client',
    requiresFiles: true,
    requiresVaultAPI: false,
    example: 'vault-audit k8s-auth audit.log',
  },
  'airflow-polling': {
    name: 'airflow-polling',
    description: 'Detect Airflow polling patterns in audit logs',
    category: 'client',
    requiresFiles: true,
    requiresVaultAPI: false,
    flags: [
      { name: '--output', description: 'Output file path', type: 'string' },
    ],
    example: 'vault-audit airflow-polling --output airflow.json audit.log',
  },
  'client-activity': {
    name: 'client-activity',
    description: 'Fetch client activity metrics from Vault API',
    category: 'vault-api',
    requiresFiles: false,
    requiresVaultAPI: true,
    flags: [
      { name: '--vault-addr', description: 'Vault server address', type: 'string', required: true },
      { name: '--vault-token', description: 'Vault authentication token', type: 'string' },
      { name: '--vault-namespace', description: 'Vault namespace', type: 'string' },
      { name: '--insecure', description: 'Skip TLS verification', type: 'bool' },
      { name: '--start-time', description: 'Start time (RFC3339)', type: 'string' },
      { name: '--end-time', description: 'End time (RFC3339)', type: 'string' },
      { name: '--entity-map', description: 'Path to entity mappings JSON', type: 'string' },
    ],
    example: 'vault-audit client-activity --vault-addr https://vault.example.com --vault-token s.xxx',
  },
  'entity-list': {
    name: 'entity-list',
    description: 'List all entities from Vault API with details',
    category: 'vault-api',
    requiresFiles: false,
    requiresVaultAPI: true,
    flags: [
      { name: '--vault-addr', description: 'Vault server address', type: 'string', required: true },
      { name: '--vault-token', description: 'Vault authentication token', type: 'string' },
      { name: '--vault-namespace', description: 'Vault namespace', type: 'string' },
      { name: '--insecure', description: 'Skip TLS verification', type: 'bool' },
      { name: '--mount', description: 'Filter by auth mount', type: 'string' },
      { name: '--output', description: 'Output file path', type: 'string' },
      { name: '--format', description: 'Output format (json or csv)', type: 'string', default: 'json' },
    ],
    example: 'vault-audit entity-list --vault-addr https://vault.example.com --vault-token s.xxx --output entities.json',
  },
  'kv-mounts': {
    name: 'kv-mounts',
    description: 'List KV mounts and enumerate secrets from Vault API',
    category: 'vault-api',
    requiresFiles: false,
    requiresVaultAPI: true,
    flags: [
      { name: '--vault-addr', description: 'Vault server address', type: 'string', required: true },
      { name: '--vault-token', description: 'Vault authentication token', type: 'string' },
      { name: '--vault-namespace', description: 'Vault namespace', type: 'string' },
      { name: '--insecure', description: 'Skip TLS verification', type: 'bool' },
      { name: '--output', description: 'Output file path', type: 'string' },
      { name: '--format', description: 'Output format (json or csv)', type: 'string', default: 'json' },
      { name: '--max-depth', description: 'Maximum recursion depth', type: 'int', default: '5' },
    ],
    example: 'vault-audit kv-mounts --vault-addr https://vault.example.com --vault-token s.xxx --max-depth 3',
  },
  'auth-mounts': {
    name: 'auth-mounts',
    description: 'List authentication mounts and their configurations from Vault API',
    category: 'vault-api',
    requiresFiles: false,
    requiresVaultAPI: true,
    flags: [
      { name: '--vault-addr', description: 'Vault server address', type: 'string', required: true },
      { name: '--vault-token', description: 'Vault authentication token', type: 'string' },
      { name: '--vault-namespace', description: 'Vault namespace', type: 'string' },
      { name: '--insecure', description: 'Skip TLS verification', type: 'bool' },
      { name: '--output', description: 'Output file path', type: 'string' },
      { name: '--format', description: 'Output format (json or csv)', type: 'string', default: 'json' },
    ],
    example: 'vault-audit auth-mounts --vault-addr https://vault.example.com --vault-token s.xxx --output auth.json',
  },
}

// Helper function to get metadata for a command
export function getCommandMetadata(command: string): CommandMetadata | undefined {
  return COMMAND_METADATA[command]
}

// Helper function to get subcommand metadata
export function getSubcommandMetadata(command: string, subcommand: string): SubcommandMetadata | undefined {
  const cmdMeta = COMMAND_METADATA[command]
  return cmdMeta?.subcommands?.find(sub => sub.name === subcommand)
}

// Made with Bob
