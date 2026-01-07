package util

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

// CronParser is a singleton cron parser with standard format (minute, hour, day, month, weekday)
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// NextCronTime calculates the next run time for a cron expression from a given start time.
// Returns the next occurrence after 'from' in UTC.
func NextCronTime(cronExpr string, from time.Time) (time.Time, error) {
	schedule, err := cronParser.Parse(cronExpr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid cron expression: %w", err)
	}
	return schedule.Next(from.UTC()), nil
}

// ValidateCronExpr checks if a cron expression is valid.
func ValidateCronExpr(cronExpr string) error {
	_, err := cronParser.Parse(cronExpr)
	if err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}
	return nil
}

// ParseCronSchedule parses a cron expression and returns the schedule.
func ParseCronSchedule(cronExpr string) (cron.Schedule, error) {
	return cronParser.Parse(cronExpr)
}
