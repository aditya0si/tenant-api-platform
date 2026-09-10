package apperr

// Sentinels returns every sentinel whose text is part of the domain's vocabulary.
//
// It exists so the HTTP layer can strip a sentinel's appended name from a wrapped
// message without keeping its own copy of the list: a second copy is a second thing
// to update, and the copy that drifts is always the one that runs.
func Sentinels() []error {
	return []error{
		ErrNotFound,
		ErrConflict,
		ErrNoScope,
		ErrForbidden,
		ErrUnauthorized,
		ErrValidation,
		ErrVersionConflict,
		ErrUnavailable,
	}
}
