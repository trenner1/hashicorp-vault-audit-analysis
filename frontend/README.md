# Vault Audit Platform - Frontend

A modern React + TypeScript + Vite frontend for the HashiCorp Vault Audit Analysis platform.

## Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tooling
- **Tailwind CSS** - Styling (via CDN)
- **TanStack Query v5** - Data fetching and caching
- **React Router v6** - Navigation
- **Recharts** - Charts (optional, for future analytics)

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

The app will be available at `http://localhost:5173` (Vite default port).

The dev server includes a proxy to the backend API:
- `/api/*` → `http://localhost:8080`
- `/healthz` → `http://localhost:8080`

### Build

```bash
npm run build
```

Outputs to `dist/` directory.

### Preview Production Build

```bash
npm run preview
```

## Configuration

### API Base URL

Set the `VITE_API_URL` environment variable to point to your backend:

```bash
VITE_API_URL=http://localhost:8080 npm run dev
```

Default: `http://localhost:8080`

See `.env.example` for template.

## Project Structure

```
frontend/
├── src/
│   ├── api/
│   │   └── client.ts          # API client and types
│   ├── components/
│   │   ├── Layout.tsx         # Main layout with sidebar nav
│   │   └── JobOutput.tsx      # Job output viewer with streaming
│   ├── pages/
│   │   ├── Dashboard.tsx      # Overview and stats
│   │   ├── Analysis.tsx       # Command selection and job submission
│   │   ├── Jobs.tsx           # Job list and details
│   │   ├── Clusters.tsx       # Cluster management
│   │   └── Settings.tsx       # Configuration and info
│   ├── App.tsx                # Router setup
│   └── main.tsx               # Entry point with providers
├── index.html                 # HTML template
├── tsconfig.json              # TypeScript config
├── vite.config.ts             # Vite config
├── package.json               # Dependencies
└── README.md                  # This file
```

## Features

### Dashboard
- Health status badge
- Quick statistics (total, running, completed jobs)
- Recent jobs table
- Links to analysis and jobs pages

### Analysis
- Command list with descriptions
- File upload (drag & drop)
- Dynamic form for command parameters
- Log file and extra flags input
- Job submission with navigation to job details

### Jobs
- Full job list with status indicators
- Real-time job status updates (3s refresh)
- Job detail panel with output viewer
- Live SSE streaming for running jobs
- Auto-scrolling terminal output

### Clusters
- List registered Vault clusters
- Add new clusters (name, address, namespace)
- Delete clusters
- Cluster management interface

### Settings
- API server configuration display
- Health check / connection test
- Application info
- Getting started guide

## Styling

The app uses **Tailwind CSS** via CDN (`<script src="https://cdn.tailwindcss.com">`). No build step required for CSS.

Color scheme:
- **Sidebar**: `bg-gray-900` (dark)
- **Main content**: `bg-gray-50` (light)
- **Primary action**: `bg-indigo-600`
- **Status badges**: Green (done), Blue (running), Gray (pending), Red (error)

## API Integration

The frontend communicates with the backend via REST API at `BASE_URL/api/v1/`. See `src/api/client.ts` for all endpoints.

### Key Endpoints

- `GET /healthz` - Health check
- `GET /api/v1/commands` - List available commands
- `POST /api/v1/jobs` - Submit a new job
- `GET /api/v1/jobs` - List all jobs
- `GET /api/v1/jobs/:id` - Get job details
- `GET /api/v1/jobs/:id/stream` - Stream job output (SSE)
- `GET /api/v1/clusters` - List clusters
- `POST /api/v1/clusters` - Create cluster
- `DELETE /api/v1/clusters/:id` - Delete cluster
- `POST /api/v1/ingest/upload` - Upload log file

## Performance

- **Data Caching**: TanStack Query with 1m stale time, 5m garbage collection
- **Automatic Refetch**: Dashboard and jobs list auto-refresh at intervals
- **SSE Streaming**: Live job output without polling
- **Lazy Loading**: Routes are dynamically loaded

## Browser Support

Modern browsers supporting ES2020:
- Chrome/Chromium 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Development Notes

- All components use functional components with hooks
- TypeScript strict mode enabled
- Tailwind CSS responsive utilities for mobile-first design
- No external component library (pure Tailwind)
- Event streaming via EventSource API for live updates

## Future Enhancements

- [ ] Charts and visualizations (Recharts integration)
- [ ] Dark mode toggle
- [ ] Advanced job filtering and search
- [ ] Export job results
- [ ] User authentication
- [ ] Log file diff viewer
- [ ] Performance analytics dashboard
