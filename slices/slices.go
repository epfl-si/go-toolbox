package slices

// RemoveDuplicates removes duplicate elements from a slice while preserving order.
// It works with any comparable type (strings, integers, etc.)
func RemoveDuplicates[T comparable](slice []T) []T {
	if len(slice) == 0 {
		return slice
	}
	
	seen := make(map[T]bool, len(slice))
	result := make([]T, 0, len(slice))
	
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}