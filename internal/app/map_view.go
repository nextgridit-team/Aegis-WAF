package app

import (
	"net/http"
	"strconv"
)

func localMapFilter(r *http.Request, name string) (bool, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return false, nil
	}
	value, e := strconv.ParseBool(raw)
	if e != nil {
		return false, invalid("invalid local traffic filter")
	}
	return value, nil
}

const localLogExclusion = " AND location_source NOT IN ('local_reference','local_unlocated')"
