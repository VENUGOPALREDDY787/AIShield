/**
 * OpenAPI 3.1 Specification for AIShield API.
 *
 * Provides machine-readable and interactive API documentation for
 * the AIShield security debt analysis platform.
 */

export const openApiSpec = {
  openapi: '3.1.0',
  info: {
    title: 'AIShield API',
    version: '0.1.0',
    description:
      'REST API for the AIShield platform — automated multi-scanner security debt scoring, contextual AI risk analysis, and Pull Request governance.',
    contact: {
      name: 'AIShield Engineering',
      url: 'https://github.com/aishield/aishield',
    },
    license: {
      name: 'Apache-2.0',
      url: 'https://www.apache.org/licenses/LICENSE-2.0.html',
    },
  },
  servers: [
    {
      url: '/',
      description: 'Current Environment Server',
    },
    {
      url: 'http://localhost:4000',
      description: 'Local Development Server',
    },
  ],
  security: [
    {
      ApiKeyAuth: [],
    },
    {
      BearerAuth: [],
    },
  ],
  paths: {
    '/health': {
      get: {
        summary: 'Liveness Probe',
        description: 'Answers from process memory to verify the service is running.',
        tags: ['Health'],
        security: [],
        responses: {
          '200': {
            description: 'Service is alive',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/HealthResponse',
                },
              },
            },
          },
        },
      },
    },
    '/health/ready': {
      get: {
        summary: 'Readiness Probe',
        description: 'Pings MongoDB and Redis to verify dependencies are healthy.',
        tags: ['Health'],
        security: [],
        responses: {
          '200': {
            description: 'All dependencies healthy',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/HealthResponse',
                },
              },
            },
          },
          '503': {
            description: 'One or more dependencies down',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/HealthResponse',
                },
              },
            },
          },
        },
      },
    },
    '/api/repositories': {
      get: {
        summary: 'List Repositories',
        description:
          'Retrieves a paginated list of repositories with optional filtering and search. Installation credentials are strictly excluded.',
        tags: ['Repositories'],
        parameters: [
          {
            name: 'page',
            in: 'query',
            description: 'Page number (1-based)',
            schema: { type: 'integer', default: 1, minimum: 1 },
          },
          {
            name: 'limit',
            in: 'query',
            description: 'Items per page',
            schema: { type: 'integer', default: 20, minimum: 1, maximum: 100 },
          },
          {
            name: 'sort',
            in: 'query',
            description: 'Sort field',
            schema: {
              type: 'string',
              enum: ['updatedAt', 'createdAt', 'fullName', 'name', 'lastScanAt'],
              default: 'updatedAt',
            },
          },
          {
            name: 'order',
            in: 'query',
            description: 'Sort direction',
            schema: { type: 'string', enum: ['asc', 'desc'], default: 'desc' },
          },
          {
            name: 'language',
            in: 'query',
            description: 'Filter by primary programming language',
            schema: { type: 'string' },
          },
          {
            name: 'archived',
            in: 'query',
            description: 'Filter archived status',
            schema: { type: 'string', enum: ['true', 'false'] },
          },
          {
            name: 'search',
            in: 'query',
            description: 'Case-insensitive search on repository full name',
            schema: { type: 'string' },
          },
        ],
        responses: {
          '200': {
            description: 'Paginated repository list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Repository' },
                    },
                    pagination: { $ref: '#/components/schemas/Pagination' },
                  },
                },
              },
            },
          },
          '401': { $ref: '#/components/responses/UnauthorizedError' },
          '429': { $ref: '#/components/responses/RateLimitError' },
        },
      },
    },
    '/api/repositories/{id}': {
      get: {
        summary: 'Get Repository Details',
        description: 'Retrieves metadata for a specific repository by its MongoDB ObjectId.',
        tags: ['Repositories'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            description: 'Repository MongoDB ObjectId',
            schema: { type: 'string', example: '652a8a91408c453c8a63c001' },
          },
        ],
        responses: {
          '200': {
            description: 'Repository details',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/Repository' },
                  },
                },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundError' },
          '422': { $ref: '#/components/responses/ValidationError' },
        },
      },
    },
    '/api/repositories/{id}/security-debt': {
      get: {
        summary: 'Get Repository Security Debt',
        description:
          'Retrieves the current security debt score (0-100), risk level, breakdown by severity and category, and scoring factors.',
        tags: ['Repositories', 'Security Debt'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            description: 'Repository MongoDB ObjectId',
            schema: { type: 'string' },
          },
        ],
        responses: {
          '200': {
            description: 'Current security debt snapshot',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/SecurityDebt' },
                  },
                },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundError' },
        },
      },
    },
    '/api/repositories/{id}/history': {
      get: {
        summary: 'Get Security Debt Trend History',
        description:
          'Retrieves the append-only ledger of historical debt score changes for trend charts and compliance audits.',
        tags: ['Repositories', 'Security Debt'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            description: 'Repository MongoDB ObjectId',
            schema: { type: 'string' },
          },
          {
            name: 'page',
            in: 'query',
            schema: { type: 'integer', default: 1 },
          },
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', default: 30, maximum: 365 },
          },
          {
            name: 'from',
            in: 'query',
            description: 'ISO date string lower bound',
            schema: { type: 'string', format: 'date-time' },
          },
          {
            name: 'to',
            in: 'query',
            description: 'ISO date string upper bound',
            schema: { type: 'string', format: 'date-time' },
          },
          {
            name: 'event',
            in: 'query',
            description: 'Filter by event type',
            schema: {
              type: 'string',
              enum: ['baseline', 'scan_completed', 'manual_recalculation', 'remediation_applied'],
            },
          },
        ],
        responses: {
          '200': {
            description: 'Paginated historical debt entries',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/SecurityDebtHistory' },
                    },
                    pagination: { $ref: '#/components/schemas/Pagination' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/repositories/{id}/findings': {
      get: {
        summary: 'List Repository Findings',
        description:
          'Retrieves durable, deduplicated security findings for this repository across all scans.',
        tags: ['Repositories', 'Findings'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            description: 'Repository MongoDB ObjectId',
            schema: { type: 'string' },
          },
          {
            name: 'severity',
            in: 'query',
            schema: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] },
          },
          {
            name: 'category',
            in: 'query',
            schema: {
              type: 'string',
              enum: [
                'injection',
                'authentication',
                'authorization',
                'secrets',
                'cryptography',
                'data_exposure',
                'dependency',
                'input_validation',
                'command_execution',
                'configuration',
                'business_logic',
                'other',
              ],
            },
          },
          {
            name: 'status',
            in: 'query',
            schema: {
              type: 'string',
              enum: ['open', 'fixed', 'false_positive', 'ignored', 'risk_accepted'],
            },
          },
          {
            name: 'source',
            in: 'query',
            schema: { type: 'string', enum: ['semgrep', 'gitleaks', 'dependency', 'ai-analyzer'] },
          },
          {
            name: 'sort',
            in: 'query',
            schema: {
              type: 'string',
              enum: ['severity', 'lastDetectedAt', 'firstDetectedAt', 'timesDetected', 'confidence'],
              default: 'lastDetectedAt',
            },
          },
          {
            name: 'order',
            in: 'query',
            schema: { type: 'string', enum: ['asc', 'desc'], default: 'desc' },
          },
          {
            name: 'file',
            in: 'query',
            description: 'Partial match on filePath',
            schema: { type: 'string' },
          },
          {
            name: 'page',
            in: 'query',
            schema: { type: 'integer', default: 1 },
          },
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', default: 20, maximum: 100 },
          },
        ],
        responses: {
          '200': {
            description: 'Paginated list of findings',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Finding' },
                    },
                    pagination: { $ref: '#/components/schemas/Pagination' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/scans': {
      post: {
        summary: 'Enqueue Security Scan',
        description:
          'Creates a new scan record and enqueues a background job in BullMQ. Idempotent: rejects duplicate in-flight scans unless force=true.',
        tags: ['Scans'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateScanRequest' },
            },
          },
        },
        responses: {
          '201': {
            description: 'Scan enqueued successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: {
                        scanId: { type: 'string' },
                        jobId: { type: 'string' },
                        status: { type: 'string', example: 'queued' },
                        commitSha: { type: 'string' },
                        branch: { type: 'string' },
                        enqueuedAt: { type: 'string', format: 'date-time' },
                      },
                    },
                  },
                },
              },
            },
          },
          '409': {
            description: 'Duplicate scan active for this commit',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ApiError' },
              },
            },
          },
          '422': { $ref: '#/components/responses/ValidationError' },
        },
      },
      get: {
        summary: 'List Scans',
        description: 'Retrieves recent scans with optional repository and status filtering.',
        tags: ['Scans'],
        parameters: [
          {
            name: 'repository',
            in: 'query',
            schema: { type: 'string' },
          },
          {
            name: 'status',
            in: 'query',
            schema: {
              type: 'string',
              enum: ['queued', 'running', 'succeeded', 'failed', 'cancelled'],
            },
          },
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', default: 20, maximum: 100 },
          },
        ],
        responses: {
          '200': {
            description: 'Recent scans list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Scan' },
                    },
                    count: { type: 'integer' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/scans/{id}': {
      get: {
        summary: 'Get Scan Status',
        description:
          'Retrieves the current execution status, component statuses (Semgrep, Gitleaks, Dependency, AI), debt score, and summary.',
        tags: ['Scans'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          '200': {
            description: 'Scan details',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/Scan' },
                  },
                },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundError' },
        },
      },
      delete: {
        summary: 'Cancel Scan',
        description: 'Cancels an in-flight or queued scan and removes it from the job queue.',
        tags: ['Scans'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          '200': {
            description: 'Scan cancelled',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: {
                        scanId: { type: 'string' },
                        status: { type: 'string', example: 'cancelled' },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/scans/{id}/report': {
      get: {
        summary: 'Get Full Scan Report',
        description:
          'Retrieves complete scan report with populated finding objects and debt delta.',
        tags: ['Scans'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          '200': {
            description: 'Comprehensive report',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/ScanReport' },
                  },
                },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundError' },
        },
      },
    },
    '/api/scans/{id}/findings': {
      get: {
        summary: 'Get Scan Findings',
        description:
          'Lists findings observed during this specific scan with filtering and pagination.',
        tags: ['Scans', 'Findings'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
          },
          {
            name: 'page',
            in: 'query',
            schema: { type: 'integer', default: 1 },
          },
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', default: 20 },
          },
          {
            name: 'severity',
            in: 'query',
            schema: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] },
          },
          {
            name: 'category',
            in: 'query',
            schema: { type: 'string' },
          },
        ],
        responses: {
          '200': {
            description: 'Findings observed in scan',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/Finding' },
                    },
                    pagination: { $ref: '#/components/schemas/Pagination' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/pull-requests/{id}': {
      get: {
        summary: 'Get Pull Request Analysis',
        description:
          'Retrieves PR security analysis, latest scan outcome, and risk delta (introduced vs resolved debt).',
        tags: ['Pull Requests'],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            description: 'Pull Request MongoDB ObjectId',
            schema: { type: 'string' },
          },
        ],
        responses: {
          '200': {
            description: 'Pull Request details',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/PullRequest' },
                  },
                },
              },
            },
          },
          '404': { $ref: '#/components/responses/NotFoundError' },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      ApiKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'x-api-key',
        description: 'Static API Key authentication header',
      },
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'API-Key',
        description: 'Bearer token authorization header',
      },
    },
    schemas: {
      Pagination: {
        type: 'object',
        properties: {
          page: { type: 'integer', example: 1 },
          limit: { type: 'integer', example: 20 },
          total: { type: 'integer', example: 42 },
          totalPages: { type: 'integer', example: 3 },
          hasNext: { type: 'boolean', example: true },
          hasPrev: { type: 'boolean', example: false },
        },
      },
      ApiError: {
        type: 'object',
        properties: {
          error: {
            type: 'object',
            properties: {
              code: { type: 'string', example: 'VALIDATION_ERROR' },
              message: { type: 'string', example: 'Request validation failed' },
              details: { type: 'object' },
              requestId: { type: 'string', example: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' },
            },
            required: ['code', 'message', 'requestId'],
          },
        },
      },
      HealthResponse: {
        type: 'object',
        properties: {
          status: { type: 'string', enum: ['ok', 'degraded'], example: 'ok' },
          service: { type: 'string', example: 'aishield-api' },
          version: { type: 'string', example: '0.1.0' },
          environment: { type: 'string', example: 'production' },
          uptimeSeconds: { type: 'number', example: 3600 },
          timestamp: { type: 'string', format: 'date-time' },
          checks: {
            type: 'object',
            additionalProperties: {
              type: 'object',
              properties: {
                status: { type: 'string', enum: ['up', 'down'] },
                latencyMs: { type: 'number' },
              },
            },
          },
        },
      },
      Repository: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          fullName: { type: 'string', example: 'octocat/hello-world' },
          name: { type: 'string', example: 'hello-world' },
          ownerLogin: { type: 'string', example: 'octocat' },
          defaultBranch: { type: 'string', example: 'main' },
          primaryLanguage: { type: 'string', example: 'TypeScript' },
          scanEnabled: { type: 'boolean', example: true },
          lastScanAt: { type: 'string', format: 'date-time' },
          lastScanStatus: { type: 'string', example: 'succeeded' },
          stats: {
            type: 'object',
            properties: {
              openFindings: { type: 'integer' },
              criticalFindings: { type: 'integer' },
            },
          },
        },
      },
      SecurityDebt: {
        type: 'object',
        properties: {
          overallScore: { type: 'number', minimum: 0, maximum: 100, example: 78.5 },
          previousScore: { type: 'number', example: 70.0 },
          delta: { type: 'number', example: 8.5 },
          grade: { type: 'string', enum: ['A', 'B', 'C', 'D', 'F'], example: 'B' },
          trend: { type: 'string', enum: ['improving', 'stable', 'worsening'], example: 'improving' },
          severityBreakdown: {
            type: 'object',
            properties: {
              CRITICAL: { type: 'integer', example: 0 },
              HIGH: { type: 'integer', example: 2 },
              MEDIUM: { type: 'integer', example: 5 },
              LOW: { type: 'integer', example: 8 },
              INFO: { type: 'integer', example: 12 },
            },
          },
          categoryBreakdown: {
            type: 'object',
            additionalProperties: { type: 'integer' },
          },
        },
      },
      SecurityDebtHistory: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          event: { type: 'string', example: 'scan_completed' },
          overallScore: { type: 'number', example: 82.0 },
          previousScore: { type: 'number', example: 78.5 },
          delta: { type: 'number', example: 3.5 },
          grade: { type: 'string', example: 'B' },
          recordedAt: { type: 'string', format: 'date-time' },
        },
      },
      Finding: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          fingerprint: { type: 'string', example: 'sha256:4f8a9...' },
          source: { type: 'string', example: 'semgrep' },
          ruleId: { type: 'string', example: 'javascript.express.security.audit.xss' },
          category: { type: 'string', example: 'injection' },
          severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] },
          confidence: { type: 'number', example: 0.95 },
          title: { type: 'string', example: 'Cross-Site Scripting (XSS) in Express Handler' },
          location: {
            type: 'object',
            properties: {
              filePath: { type: 'string', example: 'src/routes/user.ts' },
              startLine: { type: 'integer', example: 42 },
              endLine: { type: 'integer', example: 45 },
            },
          },
          status: { type: 'string', example: 'open' },
          firstDetectedAt: { type: 'string', format: 'date-time' },
          lastDetectedAt: { type: 'string', format: 'date-time' },
          timesDetected: { type: 'integer', example: 3 },
        },
      },
      CreateScanRequest: {
        type: 'object',
        required: ['repository', 'commitSha', 'branch'],
        properties: {
          repository: { type: 'string', description: 'Repository ObjectId or identifier' },
          commitSha: { type: 'string', pattern: '^[0-9a-fA-F]{40}$' },
          branch: { type: 'string', example: 'main' },
          baseSha: { type: 'string' },
          baseBranch: { type: 'string' },
          pullRequest: { type: 'string' },
          pullNumber: { type: 'integer' },
          repositoryUrl: { type: 'string', format: 'uri' },
          trigger: { type: 'string', enum: ['manual', 'pull_request', 'push', 'schedule'], default: 'manual' },
          scanners: {
            type: 'array',
            items: { type: 'string', enum: ['semgrep', 'gitleaks', 'dependency', 'ai-analyzer'] },
            default: ['semgrep', 'gitleaks', 'dependency', 'ai-analyzer'],
          },
          options: {
            type: 'object',
            properties: {
              timeoutMs: { type: 'integer', default: 300000 },
              force: { type: 'boolean', default: false },
            },
          },
        },
      },
      Scan: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          status: { type: 'string', enum: ['queued', 'running', 'succeeded', 'failed', 'cancelled'] },
          commitSha: { type: 'string' },
          branch: { type: 'string' },
          enqueuedAt: { type: 'string', format: 'date-time' },
          startedAt: { type: 'string', format: 'date-time' },
          finishedAt: { type: 'string', format: 'date-time' },
          durationMs: { type: 'integer' },
          scannerResults: { type: 'array', items: { type: 'object' } },
          finalScore: { type: 'object' },
          summary: { type: 'object' },
        },
      },
      ScanReport: {
        type: 'object',
        properties: {
          scanId: { type: 'string' },
          status: { type: 'string' },
          finalScore: { type: 'object' },
          summary: { type: 'object' },
          scannerResults: { type: 'array', items: { type: 'object' } },
          aiAnalysisStatus: { type: 'string' },
          findings: { type: 'array', items: { $ref: '#/components/schemas/Finding' } },
          startedAt: { type: 'string', format: 'date-time' },
          finishedAt: { type: 'string', format: 'date-time' },
          durationMs: { type: 'integer' },
        },
      },
      PullRequest: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          number: { type: 'integer', example: 42 },
          title: { type: 'string', example: 'feat: add oauth authentication' },
          state: { type: 'string', enum: ['open', 'closed', 'merged', 'draft'] },
          baseBranch: { type: 'string', example: 'main' },
          headBranch: { type: 'string', example: 'feat/auth' },
          headSha: { type: 'string' },
          findingsIntroduced: { type: 'integer', example: 1 },
          findingsResolved: { type: 'integer', example: 3 },
          scoreDelta: { type: 'number', example: 5.0 },
          latestScan: { type: 'object' },
        },
      },
    },
    responses: {
      UnauthorizedError: {
        description: 'Authentication credentials missing or invalid',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ApiError' },
          },
        },
      },
      NotFoundError: {
        description: 'Requested resource was not found',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ApiError' },
          },
        },
      },
      ValidationError: {
        description: 'Request payload or parameters failed validation',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ApiError' },
          },
        },
      },
      RateLimitError: {
        description: 'Request rate limit exceeded',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ApiError' },
          },
        },
      },
    },
  },
};

/** Render lightweight Swagger UI HTML page. */
export function renderSwaggerHtml(specUrl = '/api/openapi.json'): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AIShield API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  <style>
    body { margin: 0; padding: 0; background: #fafafa; font-family: sans-serif; }
    .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '${specUrl}',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>`;
}
