Installation
```
cargo add crypsol_logger
```


Environment Variables
You need to set the following environment variables to use this crate:

```
CLOUDWATCH_AWS_ACCESS_KEY: YOURS_AWS_ACCESS_KEY.
CLOUDWATCH_AWS_SECRET_KEY: YOURS_AWS_SECRET_KEY.
CLOUDWATCH_AWS_REGION: YOURS_AWS_REGION (default is us-east-1).
AWS_LOG_GROUP: YOURS_AWS_LOG_GROUP.
LOG_TO_CLOUDWATCH: Set this to false if you want to disable logging to CloudWatch (default is true).
BATCH_SIZE: The maximum number of log events to collect before sending a batch (default is 10).
BATCH_TIMEOUT: The maximum time (in seconds) to wait before flushing the current batch even if the batch size hasn't been reached (default is 5 seconds).
```

Logging Macros

You can use the log! macro to generate logs. This macro will automatically check the environment variable and accordingly send logs to CloudWatch or print them to the console.
```
log!(Level::Info, "This is an info message");
log!(Level::Error, "This is an error message");
log!(Level::Debug, "Debugging information");
```
To log in a custom stream (other than info, error and debug) you can use log_custom macro
```
log_custom!(Level::Info,"Custom Stream Name", "This is the message and variable {}",variable);

```