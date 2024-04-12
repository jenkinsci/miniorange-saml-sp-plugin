**Steps to collect log:**

* Sign in to Jenkins as an admin and select **Manage Jenkins** from the left panel of the dashboard.
  
* Scroll down to find the **System Log** option.
  ![image_1](troubleshooting/system-log.png)

* Click **Add new Log Recorder** button and add the log recorder name as **saml logs**.
* Add ```org.miniorange.saml``` as a Logger and select **fine** as a log level.
  ![image_1](troubleshooting/logger-record.png)
* Save the settings.
* Perform SSO on another browser/private window to record logs.
* Visit the **System Log** option again and copy the recorded logs from the saml logs logger.
* Paste logs in notepad/word file and send it to us.