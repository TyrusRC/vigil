package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	isTTY = lipgloss.HasDarkBackground()

	// Colors
	colorCritical = lipgloss.Color("#FF0000")
	colorHigh     = lipgloss.Color("#FF6600")
	colorMedium   = lipgloss.Color("#FFAA00")
	colorLow      = lipgloss.Color("#00AAFF")
	colorInfo     = lipgloss.Color("#888888")
	colorGreen    = lipgloss.Color("#00CC66")
	colorDim      = lipgloss.Color("#666666")
	colorWhite    = lipgloss.Color("#FFFFFF")
	colorCyan     = lipgloss.Color("#00CCCC")

	// Severity badges
	badgeCritical = lipgloss.NewStyle().Bold(true).Foreground(colorWhite).Background(colorCritical).Padding(0, 1).Render
	badgeHigh     = lipgloss.NewStyle().Bold(true).Foreground(colorWhite).Background(colorHigh).Padding(0, 1).Render
	badgeMedium   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#000000")).Background(colorMedium).Padding(0, 1).Render
	badgeLow      = lipgloss.NewStyle().Bold(true).Foreground(colorWhite).Background(colorLow).Padding(0, 1).Render
	badgeInfo     = lipgloss.NewStyle().Foreground(colorWhite).Background(colorInfo).Padding(0, 1).Render

	// Text styles
	styleBold    = lipgloss.NewStyle().Bold(true)
	styleDim     = lipgloss.NewStyle().Foreground(colorDim)
	styleURL     = lipgloss.NewStyle().Foreground(colorCyan).Underline(true)
	styleParam   = lipgloss.NewStyle().Foreground(colorMedium).Bold(true)
	styleSuccess = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	styleError   = lipgloss.NewStyle().Foreground(colorCritical)

	// Box styles
	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorCyan).
			Padding(0, 2)
)

// SeverityBadge returns a colored severity badge.
func SeverityBadge(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return badgeCritical("CRIT")
	case "high":
		return badgeHigh("HIGH")
	case "medium":
		return badgeMedium("MED")
	case "low":
		return badgeLow("LOW")
	case "info", "information":
		return badgeInfo("INFO")
	default:
		return severity
	}
}

// Banner prints the vigil startup banner.
func Banner(version string) {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(colorCyan).
		Render("vigil")
	subtitle := styleDim.Render("context-aware vulnerability scanner")
	ver := styleDim.Render("v" + version)
	fmt.Fprintf(os.Stderr, "\n  %s %s  %s\n\n", title, subtitle, ver)
}

// Target prints the target URL.
func Target(url string) {
	label := styleDim.Render("Target:")
	fmt.Fprintf(os.Stderr, "  %s %s\n", label, styleURL.Render(url))
}

// Phase prints a scan phase header.
func Phase(name string) {
	icon := styleDim.Render("›")
	fmt.Fprintf(os.Stderr, "  %s %s\n", icon, styleBold.Render(name))
}

// SubPhase prints a sub-phase detail.
func SubPhase(msg string) {
	fmt.Fprintf(os.Stderr, "    %s\n", styleDim.Render(msg))
}

// FindingInline prints a single finding as a compact inline card.
func FindingInline(idx int, severity, findingType, url, param, evidence string) {
	badge := SeverityBadge(severity)
	num := styleDim.Render(fmt.Sprintf("#%d", idx))
	ftype := styleBold.Render(findingType)
	u := styleURL.Render(url)

	fmt.Fprintf(os.Stderr, "\n  %s %s %s\n", num, badge, ftype)
	fmt.Fprintf(os.Stderr, "     %s\n", u)
	if param != "" {
		fmt.Fprintf(os.Stderr, "     param: %s\n", styleParam.Render(param))
	}
	if evidence != "" {
		ev := evidence
		if len(ev) > 200 {
			ev = ev[:200] + "..."
		}
		fmt.Fprintf(os.Stderr, "     %s\n", styleDim.Render(ev))
	}
}

// Summary prints the severity summary counts.
func Summary(critical, high, medium, low, info int, duration string) {
	total := critical + high + medium + low + info
	parts := []string{}
	if critical > 0 {
		parts = append(parts, badgeCritical(fmt.Sprintf("%d", critical)))
	}
	if high > 0 {
		parts = append(parts, badgeHigh(fmt.Sprintf("%d", high)))
	}
	if medium > 0 {
		parts = append(parts, badgeMedium(fmt.Sprintf("%d", medium)))
	}
	if low > 0 {
		parts = append(parts, badgeLow(fmt.Sprintf("%d", low)))
	}
	if info > 0 {
		parts = append(parts, badgeInfo(fmt.Sprintf("%d", info)))
	}

	fmt.Fprintf(os.Stderr, "\n")
	if total == 0 {
		fmt.Fprintf(os.Stderr, "  %s No vulnerabilities found\n", styleSuccess.Render("✓"))
	} else {
		fmt.Fprintf(os.Stderr, "  %s %d findings  %s\n",
			styleBold.Render("Findings:"),
			total,
			strings.Join(parts, " "))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n\n", styleDim.Render("Duration:"), duration)
}

// SavedReport prints the auto-save notification.
func SavedReport(path string) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", styleSuccess.Render("✓ Report saved:"), path)
}

// Error prints an error message.
func Error(msg string) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", styleError.Render("✗"), msg)
}

// ProgressLine prints an inline progress update (overwrites current line).
func ProgressLine(phase string, current, total int, findings int, elapsed string) {
	pct := 0
	if total > 0 {
		pct = current * 100 / total
	}
	bar := renderBar(pct, 20)
	fmt.Fprintf(os.Stderr, "\r  %s %s %d/%d %s %s",
		styleDim.Render(elapsed),
		bar,
		current, total,
		styleDim.Render(phase),
		findingsCounter(findings))
}

func renderBar(pct, width int) string {
	filled := pct * width / 100
	empty := width - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	style := lipgloss.NewStyle().Foreground(colorCyan)
	return style.Render(bar) + styleDim.Render(fmt.Sprintf(" %d%%", pct))
}

func findingsCounter(n int) string {
	if n == 0 {
		return ""
	}
	return styleError.Render(fmt.Sprintf("(%d found)", n))
}
