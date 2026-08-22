//go:build !windows

package main

func prepareJSONValue(path string, value any) (any, error) {
	return prepareServerJSONValue(path, value)
}

func restoreJSONValue(path string, value any) error {
	return restoreServerJSONValue(path, value)
}
