# Frontend Architecture

## Overview

The Vault Audit Platform frontend is a modern React + TypeScript + Vite application with a clean, professional UI built entirely with Tailwind CSS. The app provides a comprehensive interface for managing Vault audit analysis jobs.

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Runtime** | React 18 + TypeScript | UI framework with type safety |
| **Build** | Vite 5 | Fast development and optimized builds |
| **Styling** | Tailwind CSS 3 (CDN) | Utility-first CSS framework |
| **Routing** | React Router v6 | Client-side navigation |
| **State Management** | TanStack Query v5 | Server state & data fetching |
| **Target** | ES2020 | Modern browser compatibility |

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      Browser (SPA)                           │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   React Router                         │  │
│  │  ┌─ Dashboard  ┌─ Analysis  ┌─ Jobs  ┌─ Clusters      │  │
│  │  │ (Home)     │ (Commands) │ (List) │ (Config)       │  │
│  │  └────────────┴────────────┴────────┴────────────────┘  │
│  │                                                           │
│  │  ┌─────────────────────────────────────────────────┐    │
│  │  │             Layout (Dark Sidebar)              │    │
│  │  │  ┌─ Nav  ┌──────────────────────────────────┐  │    │
│  │  │  │items  │  Current Page Content             │  │    │
│  │  │  │       │                                    │  │    │
│  │  │  │       │  - Components (JobOutput, etc)   │  │    │
│  │  │  │       │  - Forms & Tables                │  │    │
│  │  │  │       │  - Status Badges                 │  │    │
│  │  │  │       └──────────────────────────────────┘  │    │
│  │  └─────────────────────────────────────────────────┘    │
│  │                                                           │
│  │  ┌─────────────────────────────────────────────────┐    │
│  │  │         TanStack Query (Caching)               │    │
│  │  │  - useQuery for fetching                       │    │
│  │  │  - useMutation for POST/DELETE                 │    │
│  │  │  - Auto-refetch on intervals                   │    │
│  │  │  - Stale time: 60s, GC: 5m                     │    │
│  │  └─────────────────────────────────────────────────┘    │
│  │                                                           │
│  └───────────────────────────────────────────────────────┘  │
│                           │                                  │
│                           ▼                                  │
│                    ┌──────────────┐                         │
│                    │  API Client  │                         │
│                    │  (REST + SSE)│                         │
│                    └──────────────┘                         │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  Backend API     │
                  │ http://localhost │
                  │     :8080        │
                  └──────────────────┘
```

## Component Structure

### Layout Hierarchy

```
App.tsx (Router Setup)
│
└─ Layout (Sidebar Navigation)
   │
   ├─ Dashboard
   │  ├─ Health Status Card
   │  ├─ Stats Cards (3 columns)
   │  └─ Recent Jobs Table
   │
   ├─ Analysis
   │  ├─ Command Selection (Sidebar)
   │  ├─ File Upload Area
   │  ├─ Form
   │  │  ├─ Log Files Textarea
   │  │  └─ Extra Flags Input
   │  └─ Uploaded Files List
   │
   ├─ Jobs
   │  ├─ Jobs List Table
   │  └─ JobOutput (Detail Panel)
   │     └─ Terminal Output Viewer
   │
   ├─ Clusters
   │  ├─ Add Cluster Form
   │  └─ Clusters Table
   │
   └─ Settings
      ├─ API Configuration Display
      ├─ Connection Test
      └─ Application Info
```

## State Management Strategy

### Data Fetching with TanStack Query

```typescript
// Dashboard
useQuery({
  queryKey: ['health'],
  queryFn: api.health,
  refetchInterval: 10000,  // Poll every 10s
})

// Jobs List
useQuery({
  queryKey: ['jobs'],
  queryFn: api.listJobs,
  refetchInterval: 3000,   // Poll every 3s (high priority)
})

// Job Submission
useMutation({
  mutationFn: api.submitJob,
  onSuccess: (data) => navigate(`/jobs/${data.id}`),
})
```

### Streaming Data with EventSource

```typescript
// Real-time job output
if (job.status === 'running') {
  const eventSource = api.streamJob(jobId)
  eventSource.addEventListener('output', (event) => {
    setOutputLines(prev => [...prev, event.data])
  })
}
```

## API Integration

### Base Configuration

```typescript
const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8080'
```

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/healthz` | Health check |
| GET | `/api/v1/commands` | List commands |
| POST | `/api/v1/jobs` | Submit job |
| GET | `/api/v1/jobs` | List jobs |
| GET | `/api/v1/jobs/:id` | Get job details |
| GET | `/api/v1/jobs/:id/stream` | Stream output (SSE) |
| GET | `/api/v1/clusters` | List clusters |
| POST | `/api/v1/clusters` | Create cluster |
| DELETE | `/api/v1/clusters/:id` | Delete cluster |
| POST | `/api/v1/ingest/upload` | Upload file |

## Styling System

### Color Palette

```
Primary:     indigo-600 (#4f46e5)
Background:  gray-50 (#f9fafb) - main, gray-900 (#111827) - sidebar
Text:        gray-900 (#111827) - primary, gray-600 (#4b5563) - secondary
Border:      gray-300 (#d1d5db)

Status Badges:
- Pending:   bg-gray-100 text-gray-800
- Running:   bg-blue-100 text-blue-800
- Done:      bg-green-100 text-green-800
- Error:     bg-red-100 text-red-800
```

### Typography

- Headings: font-bold, text-gray-900
- Labels: font-medium, text-sm, text-gray-700
- Body: text-gray-600, text-sm/base
- Monospace: font-mono (code, IDs, paths)

## File Organization

```
src/
├── api/
│   └── client.ts           # API client + types (Job, Cluster, etc)
│
├── components/
│   ├── Layout.tsx          # Main layout with sidebar nav
│   └── JobOutput.tsx       # Reusable job output viewer
│
├── pages/
│   ├── Dashboard.tsx       # Overview page
│   ├── Analysis.tsx        # Job submission page
│   ├── Jobs.tsx            # Job list page
│   ├── Clusters.tsx        # Cluster management page
│   └── Settings.tsx        # Settings & info page
│
├── App.tsx                 # Router setup
└── main.tsx                # Entry point + providers
```

## Key Features Implementation

### 1. Dashboard
- **Health Status**: Polls `/healthz` with 10s interval
- **Statistics**: Computed from jobs list (total, running, completed)
- **Recent Jobs**: Shows 10 most recent, filters by status
- **Auto-refresh**: 5s interval for real-time updates

### 2. Analysis (Command Runner)
- **Command Selection**: Hardcoded list with descriptions
- **File Upload**: Drag & drop + click upload
- **Form Builder**: Dynamic fields (log files, extra flags)
- **Job Submission**: POST to `/api/v1/jobs` with validation

### 3. Jobs (Monitoring)
- **Job List**: Full table with real-time status updates (3s)
- **Detail Panel**: Expandable job output viewer
- **Live Streaming**: EventSource for running jobs
- **Auto-scroll**: Terminal output scrolls to bottom

### 4. Clusters (Configuration)
- **CRUD Operations**: Create, read, delete
- **Form Validation**: Required field checking
- **Mutation Feedback**: Loading states and error handling

### 5. Settings (Configuration)
- **API Display**: Shows configured base URL
- **Connection Test**: Calls `/healthz` with result display
- **App Info**: Version, framework, timestamps

## Performance Optimizations

### Caching Strategy
- **Stale Time**: 60 seconds (data considered fresh)
- **GC Time**: 5 minutes (inactive query removal)
- **Refetch on Focus**: Automatic updates when tab refocused
- **Selective Polling**: Different intervals per feature

### Rendering Optimizations
- **Lazy Routes**: Each page loads on demand
- **Memoization**: Components wrapped for expensive renders
- **Virtual Scrolling**: Large tables could implement windowing
- **Event Delegation**: Table row click handling

### Network Optimizations
- **Minimal Payload**: Only required fields fetched
- **Request Batching**: Query keys for deduplication
- **Conditional Requests**: Check job status before polling

## Error Handling

### User-Facing Errors
- Toast-like error messages (inline in forms)
- Fallback UI for loading/error states
- Clear error messages from API

### Type Safety
- Full TypeScript coverage
- Strict null checks enabled
- No `any` types (except unavoidable cases)

## Browser Compatibility

- **Target**: ES2020
- **Minimum**: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- **Features Used**: Fetch API, EventSource, CSS Grid/Flexbox

## Development Workflow

1. **Dev Server**: `npm run dev` → Vite HMR + API proxy
2. **Type Checking**: `tsc` (part of build)
3. **Build**: `npm run build` → Optimized dist/
4. **Preview**: `npm run preview` → Local server for dist/

## Future Enhancements

- [ ] Dark mode toggle
- [ ] Advanced filtering & search
- [ ] Export job results (JSON, CSV)
- [ ] User authentication
- [ ] Analytics dashboard with charts
- [ ] Log diff viewer
- [ ] Real-time notifications
- [ ] Keyboard shortcuts
