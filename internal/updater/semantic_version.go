package updater

import (
	"fmt"
	"strconv"
	"strings"
)

// compareVersions 比较版本号，如果 latest > current 返回 true
func compareVersions(current, latest string) bool {
	currentVer, errCurr := parseSemanticVersion(current)
	latestVer, errLatest := parseSemanticVersion(latest)
	if errCurr == nil && errLatest == nil {
		return latestVer.compare(currentVer) > 0
	}

	// 解析失败时降级为简单比较
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")
	return latest != current
}

type semanticVersion struct {
	major      int    // major 是不兼容 API 变更版本号。
	minor      int    // minor 是向后兼容功能版本号。
	patch      int    // patch 是向后兼容修复版本号。
	prerelease string // prerelease 是不含前导连字符的预发布标识。
}

// parseSemanticVersion 解析兼容可选 v 前缀和短版本号的语义版本。
func parseSemanticVersion(raw string) (semanticVersion, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "v")
	if raw == "" {
		return semanticVersion{}, fmt.Errorf("empty version")
	}

	if idx := strings.Index(raw, "+"); idx >= 0 {
		raw = raw[:idx]
	}
	var prerelease string
	if idx := strings.Index(raw, "-"); idx >= 0 {
		prerelease = raw[idx+1:]
		raw = raw[:idx]
	}
	if prerelease != "" {
		for _, identifier := range strings.Split(prerelease, ".") {
			if identifier == "" || strings.IndexFunc(identifier, func(character rune) bool {
				return !((character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '-')
			}) >= 0 {
				return semanticVersion{}, fmt.Errorf("invalid prerelease: %s", prerelease)
			}
		}
	}

	parts := strings.Split(raw, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semanticVersion{}, fmt.Errorf("invalid version: %s", raw)
	}

	parsePart := func(idx int) (int, error) {
		if idx >= len(parts) || parts[idx] == "" {
			return 0, nil
		}
		return strconv.Atoi(parts[idx])
	}

	major, err := parsePart(0)
	if err != nil {
		return semanticVersion{}, err
	}
	minor, err := parsePart(1)
	if err != nil {
		return semanticVersion{}, err
	}
	patch, err := parsePart(2)
	if err != nil {
		return semanticVersion{}, err
	}

	return semanticVersion{
		major:      major,
		minor:      minor,
		patch:      patch,
		prerelease: prerelease,
	}, nil
}

// compare 按 Semantic Versioning 2.0.0 规则比较两个版本。
func (v semanticVersion) compare(other semanticVersion) int {
	if v.major != other.major {
		if v.major > other.major {
			return 1
		}
		return -1
	}

	if v.minor != other.minor {
		if v.minor > other.minor {
			return 1
		}
		return -1
	}

	if v.patch != other.patch {
		if v.patch > other.patch {
			return 1
		}
		return -1
	}

	if v.prerelease == other.prerelease {
		return 0
	}

	if v.prerelease == "" {
		return 1
	}
	if other.prerelease == "" {
		return -1
	}

	return comparePrerelease(v.prerelease, other.prerelease)
}

// comparePrerelease 按点分标识符比较预发布版本，数字标识符按数值排序。
func comparePrerelease(first, second string) int {
	firstParts := strings.Split(first, ".")
	secondParts := strings.Split(second, ".")
	limit := min(len(firstParts), len(secondParts))
	for index := 0; index < limit; index++ {
		firstNumber, firstNumeric := parsePrereleaseNumber(firstParts[index])
		secondNumber, secondNumeric := parsePrereleaseNumber(secondParts[index])
		switch {
		case firstNumeric && secondNumeric && firstNumber != secondNumber:
			if firstNumber > secondNumber {
				return 1
			}
			return -1
		case firstNumeric != secondNumeric:
			if firstNumeric {
				return -1
			}
			return 1
		case firstParts[index] != secondParts[index]:
			return strings.Compare(firstParts[index], secondParts[index])
		}
	}
	if len(firstParts) == len(secondParts) {
		return 0
	}
	if len(firstParts) > len(secondParts) {
		return 1
	}
	return -1
}

// parsePrereleaseNumber 返回预发布标识符的数字值和是否为纯数字。
func parsePrereleaseNumber(identifier string) (int, bool) {
	for _, character := range identifier {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	value, err := strconv.Atoi(identifier)
	return value, err == nil
}
