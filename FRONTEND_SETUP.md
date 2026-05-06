# Frontend Setup & Deployment Guide

## Location

The frontend application is located at:
```
/sessions/loving-vibrant-dijkstra/mnt/hashicorp-vault-audit-analysis/frontend/
```

## Quick Start

### 1. Install Dependencies

```bash
cd frontend
npm install
```

### 2. Start Development Server

```bash
npm run dev
```

The app will be available at `http://localhost:5173`

### 3. Configure API URL (if needed)

The frontend proxies API calls to `http://localhost:8080` by default. If your backend is on a different host/port:

```bash
# Option 1: Environment variable
VITE_API_URL=http://api.example.com:8080 npm run dev

# Option 2: Create .env.local
echo "VITE_API_URL=http://api.example.com:8080" > .env.local
npm run dev
```

See `.env.example` for template.

## Build for Production

```bash
npm run build
```

This generates an optimized build in the `dist/` directory.

### Deploy to Hosting

The `dist/` directory contains a static SPA. Deploy it to any static hosting:
- Netlify
- Vercel
- AWS S3 + CloudFront
- GitHub Pages
- Your own web server

## Project Structure

```
frontend/
├── src/
│   ├── api/               # API client with types
│   ├── components/        # Reusable components
│   ├── pages/             # Page components (5 routes)
│   ├── App.tsx            # Router setup
│   └── main.tsx           # Entry point
├── index.html             # HTML template
├── vite.config.ts         # Build config
├── tsconfig.json          # TypeScript config
├── package.json           # Dependencies
└── [documentation files]
```

## Features Implemented

### Pages
- **Dashboard** (`/`) - Overview, stats, recent jobs
- **Analysis** (`/analysis`) - Run analysis jobs
- **Jobs** (`/jobs`) - Monitor and view job details
- **Clusters** (`/clusters`) - Manage Vault clusters
- **Settings** (`/settings`) - Configuration and testing

### Key Capabilities
- Real-time job status updates
- Live output streaming (SSE)
- File upload (drag & drop)
- Dark sidebar navigation
- Status badges with colors
- Terminal-style output viewer
- API connection testing

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| UI Framework | React | 18.3.1 |
| Language | TypeScript | 5.5.3 |
| Build Tool | Vite | 5.4.3 |
| Styling | Tailwind CSS | 3 (CDN) |
| Data Fetching | TanStack Query | 5.56.2 |
| Routing | React Router | 6.26.2 |
| Real-time | EventSource (SSE) | Native |

## Configuration Reference

### Environment Variables

```env
# API base URL (default: http://localhost:8080)
VITE_API_URL=http://localhost:8080
```

### Development Server

- **Port**: 5173 (Vite default)
- **API Proxy**: `/api/*` and `/healthz/*` → backend
- **Hot Reload**: Enabled
- **TypeScript Check**: On save

### Build Output

- **Directory**: `dist/`
- **Size**: ~300KB (gzipped ~100KB)
- **Target**: ES2020
- **Format**: ESM with index.html

## API Integration

The frontend communicates with:
```
http://localhost:8080/api/v1/*
http://localhost:8080/healthz
```

### Supported Endpoints

- `GET /healthz` - Health check
- `GET /api/v1/commands` - List commands
- `POST /api/v1/jobs` - Submit job
- `GET /api/v1/jobs` - List jobs
- `GET /api/v1/jobs/:id` - Get job
- `GET /api/v1/jobs/:id/stream` - Stream output
- `GET /api/v1/clusters` - List clusters
- `POST /api/v1/clusters` - Create cluster
- `DELETE /api/v1/clusters/:id` - Delete cluster
- `POST /api/v1/ingest/upload` - Upload file

## Troubleshooting

### Port Already in Use

```bash
# Use a different port
npm run dev -- --port 3000
```

### API Connection Issues

1. Check if backend is running on the configured URL
2. Verify VITE_API_URL environment variable
3. Test connection in Settings page
4. Check browser console for CORS errors

### Build Errors

```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
npm run build
```

### TypeScript Errors

```bash
# Check types
npx tsc --noEmit
```

## Development Workflow

### Add a New Page

1. Create `src/pages/NewPage.tsx`
2. Add route in `src/App.tsx`
3. Add nav item in `src/components/Layout.tsx`
4. Add API client methods in `src/api/client.ts`

### Add a New Component

1. Create `src/components/NewComponent.tsx`
2. Export from component file
3. Import and use in pages

### Update Styles

Tailwind classes are applied directly in components. No CSS files needed.

## Performance Notes

- Dashboard auto-refreshes every 5 seconds
- Jobs list auto-refreshes every 3 seconds
- Job detail streams via EventSource
- Queries cached for 60 seconds
- Garbage collection after 5 minutes

## Browser Support

Modern browsers supporting ES2020:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Security Considerations

- No hardcoded credentials
- API URL configurable
- No sensitive data in localStorage
- CORS handled by backend proxy
- TypeScript for type safety

## Monitoring

Monitor the application using:
1. Browser DevTools (Network, Console)
2. Settings page (Test Connection)
3. Dashboard (Health Status)
4. Jobs page (Output logs)

## Support Files

- `README.md` - Full documentation
- `QUICKSTART.md` - Quick start guide
- `ARCHITECTURE.md` - Technical details
- `BUILD_SUMMARY.md` - Build completion report

## Next Steps

1. `npm install` - Install dependencies
2. `npm run dev` - Start development
3. `npm run build` - Build for production
4. Deploy `dist/` to hosting

---

Frontend Version: 0.1.0
Last Updated: 2026-04-05
Status: Ready for Production
