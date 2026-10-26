package app

import (
	"context"
	"github.com/jackc/pgx/v5"
	"strconv"
)

const communityFeedURL = "https://api.github.com/repos/nextgridit-team/Aegis-WAF/contents/rules/community/manifest.json"

func seedCommunityFeed(ctx context.Context, tx pgx.Tx) error {
	var exists bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM built_in_rule_feeds WHERE key='aegis-community')").Scan(&exists); e != nil {
		return e
	}
	if exists {
		return nil
	}
	var id *int64
	if e := tx.QueryRow(ctx, "SELECT min(id) FROM rule_feeds WHERE site_id IS NULL AND url=$1", communityFeedURL).Scan(&id); e != nil {
		return e
	}
	if id == nil {
		var count int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM rule_feeds").Scan(&count); e != nil {
			return e
		}
		if count < 20 {
			if e := tx.QueryRow(ctx, "INSERT INTO rule_feeds(name,url,site_id) VALUES('Aegis community mitigations',$1,NULL) RETURNING id", communityFeedURL).Scan(&id); e != nil {
				return e
			}
		}
	}
	_, e := tx.Exec(ctx, "INSERT INTO built_in_rule_feeds(key,feed_id) VALUES('aegis-community',$1)", id)
	return e
}

// Retire only the old official example subscription. Imported native rules and
// custom sources are independent records and must retain their working state.
func retireStarterFeed(ctx context.Context, tx pgx.Tx) error {
	var exists bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM built_in_rule_feeds WHERE key='starter-retired')").Scan(&exists); e != nil {
		return e
	}
	if exists {
		return nil
	}
	rows, e := tx.Query(ctx, "DELETE FROM rule_feeds WHERE url=$1 RETURNING id", "https://api.github.com/repos/nextgridit-team/Aegis-WAF/contents/rules/starter.json")
	if e != nil {
		return e
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = audit(ctx, tx, "system", "feed.starter_retired", strconv.FormatInt(id, 10)); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, "INSERT INTO built_in_rule_feeds(key,feed_id) VALUES('starter-retired',NULL)")
	return e
}
