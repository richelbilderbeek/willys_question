# Problem
# Write an event to the syslog in ArcSight CEF format
# Example:
# Jun 16 08:54:03 myserver.mycompany.nl CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232


### First option: rsyslog package ####

library(rsyslog)

syslog("CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232")
close_syslog()

# Output in syslog:
# Jun 16 08:51:04 myserver rsession-testuser[19090]: CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

open_syslog(identifier = NULL, include_pid = FALSE)
syslog("CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232")
close_syslog()
# Output in syslog:
# Jun 16 08:54:03 myserver rsession[19090]: CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

# Question: How do I change the prefix of the message?
# Host should by a fully qualified domain name and rsession[pid] should be dropped from the prefix.

#### Second option: log4r package ####

library(log4r)

# Create a new logger object with create.logger().
logger <- create.logger(logfile = "test.log", level = "WARN")
warn(logger, "CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232")
# Output in test.log:
# WARN  [2020-06-16 09:00:30] CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

# Log to console
appender <- console_appender()
appender("INFO", "Input has length ", 0, ".")

# Different layouts
simple <- simple_log_layout()
simple("INFO", "Input has length ", 0, ".")
with_timestamp <- default_log_layout()
with_timestamp("INFO", "Input has length ", 0, ".")

# Custom layout
my_layout <- function(level, host, message) {
  msg <- paste(format(Sys.time(), "%b %d %H:%M:%S"), host, message, collapse = "")
}

appender <- console_appender(layout = my_layout)
appender("WARN", host = "myserver.mycompany.nl", message = "CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232")
# Output to console:
# Jun 16 09:40:16 myserver.mycompany.nl CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

appender <- file_appender(file= 'test.log', append = TRUE, layout = my_layout)
appender("WARN", host = "myserver.mycompany.nl", message = "CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232")
# Output in test.log:
# Jun 16 09:44:23 myserver.mycompany.nl CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

appender <- file_appender(file= '/var/log/syslog', append = TRUE, layout = my_layout)
appender("WARN", host = "myserver.mycompany.nl", message = "CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232")
# ERROR:
# cannot open file '/var/log/syslog': Permission denied

# Question: How can I write an event to the syslog using log4r?

