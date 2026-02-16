# Setting Up Real GitHub Badges

This guide explains how to replace placeholder badges with real, live badges that show actual project metrics.

## Current Status

The README currently has placeholder badges. Follow these steps to enable real badges:

## 1. GitHub Actions Build Badge

**Current (Placeholder):**
```markdown
![Build-Passing](https://img.shields.io/badge/Build-Passing-success?style=for-the-badge)
```

**Replace with:**
```markdown
[![CI](https://github.com/YOUR_USERNAME/go-hunter/workflows/CI/badge.svg)](https://github.com/YOUR_USERNAME/go-hunter/actions)
```

**Steps:**
1. Push your code to GitHub
2. GitHub Actions will automatically run (already configured in `.github/workflows/ci.yml`)
3. Badge will show real CI status

## 2. Codecov Coverage Badge

**Current:** No coverage badge

**Add:**
```markdown
[![codecov](https://codecov.io/gh/YOUR_USERNAME/go-hunter/branch/main/graph/badge.svg)](https://codecov.io/gh/YOUR_USERNAME/go-hunter)
```

**Steps:**
1. Sign up at [codecov.io](https://codecov.io) (free for open source)
2. Connect your GitHub repository
3. Add `CODECOV_TOKEN` to GitHub repository secrets:
   - Go to repository Settings → Secrets → Actions
   - Click "New repository secret"
   - Name: `CODECOV_TOKEN`
   - Value: (from Codecov dashboard)
4. CI already uploads coverage (see `.github/workflows/ci.yml` lines 62-69)
5. Badge will show real coverage percentage

## 3. Go Report Card Badge

**Current (Placeholder):**
```markdown
![Go Report-A+](https://img.shields.io/badge/Go%20Report-A+-brightgreen?style=for-the-badge)
```

**Replace with:**
```markdown
[![Go Report Card](https://goreportcard.com/badge/github.com/YOUR_USERNAME/go-hunter)](https://goreportcard.com/report/github.com/YOUR_USERNAME/go-hunter)
```

**Steps:**
1. Push code to public GitHub repository
2. Visit [goreportcard.com](https://goreportcard.com)
3. Enter your repository URL and click "Generate Report"
4. Report updates automatically on each push
5. Add badge URL to README

## 4. GoDoc Badge

**Add:**
```markdown
[![GoDoc](https://pkg.go.dev/badge/github.com/YOUR_USERNAME/go-hunter)](https://pkg.go.dev/github.com/YOUR_USERNAME/go-hunter)
```

**Steps:**
1. Push code to public GitHub repository
2. Visit [pkg.go.dev](https://pkg.go.dev)
3. Search for your repository
4. Documentation auto-generates from comments
5. Add badge URL to README

## 5. License Badge

**Current (correct):**
```markdown
[![License-MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
```

**Status:** ✅ Already correct (points to LICENSE file)

## Final README Badges Section

Replace lines 12-16 in README.md with:

```markdown
<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.22+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT"></a>
  <a href="https://github.com/YOUR_USERNAME/go-hunter/actions"><img src="https://github.com/YOUR_USERNAME/go-hunter/workflows/CI/badge.svg" alt="Build Status"></a>
  <a href="https://goreportcard.com/report/github.com/YOUR_USERNAME/go-hunter"><img src="https://goreportcard.com/badge/github.com/YOUR_USERNAME/go-hunter" alt="Go Report Card"></a>
  <a href="https://codecov.io/gh/YOUR_USERNAME/go-hunter"><img src="https://codecov.io/gh/YOUR_USERNAME/go-hunter/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://pkg.go.dev/github.com/YOUR_USERNAME/go-hunter"><img src="https://pkg.go.dev/badge/github.com/YOUR_USERNAME/go-hunter" alt="GoDoc"></a>
</p>
```

**Remember to replace `YOUR_USERNAME` with your actual GitHub username!**

## Expected Results

Once configured, badges will show:

- **Go 1.22+**: Static badge (already correct)
- **License MIT**: Static badge (already correct)
- **Build Status**: ✅/❌ based on CI results
- **Go Report Card**: A+ to F grade based on code quality
- **Coverage**: 23.6% (and growing!)
- **GoDoc**: Links to auto-generated documentation

## Benefits

1. **Professionalism**: Shows this is a well-maintained project
2. **Transparency**: Visitors see quality metrics at a glance
3. **Credibility**: Real badges > placeholder badges
4. **Monitoring**: You'll see if CI breaks or coverage drops

## Verification Checklist

- [ ] Push code to GitHub
- [ ] CI builds successfully
- [ ] Set up Codecov account and add token
- [ ] Generate Go Report Card
- [ ] Update README with real badge URLs
- [ ] Verify all badges show correct data

## Troubleshooting

**Badge shows "unknown":**
- Repository might not be public
- Service might need time to index (wait 5-10 minutes)
- Check that repository URL is correct

**Coverage not uploading:**
- Verify `CODECOV_TOKEN` is set in GitHub secrets
- Check CI logs for upload errors
- Ensure `coverage.out` file is generated

**Go Report Card not updating:**
- It caches results for 24 hours
- Click "Refresh" on goreportcard.com to force update
- Ensure code is pushed to main branch
