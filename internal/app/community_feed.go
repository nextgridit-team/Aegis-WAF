package app

import (
	"context"
	"github.com/jackc/pgx/v5"
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
