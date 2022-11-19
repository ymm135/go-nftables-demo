package strerror

type FDStringError struct {
	name string
}

func (e *FDStringError) Error() string {
	return e.name
}

func CreateError(name string) error {
	return &FDStringError{name}
}
