# Quick Start Guide

## Installation & Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The app will be available at `http://localhost:5173`

### With Backend API

If your backend is running on a different port, set the API URL:

```bash
VITE_API_URL=http://localhost:8080 npm run dev
```

## Building for Production

```bash
npm run build
```

Output goes to `dist/` directory.

## Project Features

### Pages

1. **Dashboard** (`/`)
   - Health status indicator
   - Job statistics
   - Recent jobs list
   - Quick action buttons

2. **Analysis** (`/analysis`)
   - Command selection
   - File upload (drag & drop)
   - Dynamic form builder
   - Job submission

3. **Jobs** (`/jobs`)
   - Job list with status
   - Real-time updates
   - Live output streaming
   - Job detail panel

4. **Clusters** (`/clusters`)
   - Cluster management
   - Add/delete operations
   - Configuration storage

5. **Settings** (`/settings`)
   - API configuration
   - Connection testing
   - Application info

### Key Technologies

- **React 18** with TypeScript
- **Tailwind CSS** (CDN, no build step)
- **Vite** for fast development
- **TanStack Query** for data fetching
- **React Router** for navigation

## API Integration

The frontend communicates with the backend API. Key endpoints:

- `GET /healthz` - Health check
- `POST /api/v1/jobs` - Submit job
- `GET /api/v1/jobs` - List jobs
- `GET /api/v1/jobs/:id/stream` - Live output (SSE)

## Troubleshooting

### API Connection Issues

If you see connection errors:

1. Verify backend is running on `http://localhost:8080`
2. Check VITE_API_URL environment variable
3. Look at browser console for network errors
4. Test connection in Settings page

### Dependencies Issues

```bash
# Clear and reinstall
rm -rf node_modules package-lock.json
npm install
```

## Environment Variables

Create `.env.local` to override defaults:

```
VITE_API_URL=http://your-api-url:8080
```

See `.env.example` for template.

## File Structure

```
frontend/
├── src/
│   ├── api/          # API client
│   ├── components/   # Reusable components
│   ├── pages/        # Page components
│   ├── App.tsx       # Router setup
│   └── main.tsx      # Entry point
├── index.html        # HTML template
├── vite.config.ts    # Vite config
└── tsconfig.json     # TypeScript config
```

## Next Steps

1. Install dependencies: `npm install`
2. Start dev server: `npm run dev`
3. Open browser at `http://localhost:5173`
4. Configure API URL in Settings if needed
5. Start running analyses!
