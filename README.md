# Onboarding Instructions
## Intial Configuration and prerequisites
1. Download all *.sh files in this repo.
2. If you have not already done so, ensure your local password meets the following requirements:
   1. Length: 14+ characters
   2. lowercase: at least 1
   3. upercase: at least 1
   4. number: at least 1
   5. special: at least 1
3. Update your device with one of the following options:
   1. Open terminal through the GUI (Show Apps) or with ctrl+alt+t
      1. Type in this command, and let it complete
      2. ```sudo apt update && sudo apt upgrade -y```
   2. Alternatively, you can update via the GUI (Show Apps > Software Updater)
   3. Next, update all software not managed by apt
      1. Open App Center from your Dash
      2. Click on Manage in the lower left hand corner
      3. Click Update All
4. Install the prerequisites via terminal
   1. Open Terminal
   2. Navigate to where you downloaded the sh file earlier (Firefox defaults to **$Home/Downloads**)
   3. For each sh file run the following command:
   4. ```chmod +x <filename>.sh```
   5. Run each sh file with sudo:
   6. ```sudo ./<filename>.sh```
   7. Ignore any reboot requests until all scripts have run.
   8. Reboot
## Configure GRUB password
1. Open a Terminal window
2. Type in the following command:
   1. ```sudo grub-mkpasswd-pbkdf2```
3. Terminal will prompt you for your sudo password (same as login password)
4. Terminal will prompt you for a GRUB password.
   1. ***Recommend this password be different from your login password, as your login password will be changing every 60 days.***
   2.	Use a password manager or remember your password.
5.	Copy the generated hash
   1. Example hash: ```grub.pbkdf2.sha512.10000.095DB0192324CCACC86DB81455C7E45B266FA9570CAFE8FC413A4C756F6666A35CD907EB73BE95D2C469CAA9C8FEB0F278365738B1FD7AB96EDFA15D0442D8D7.2EC836CCB165599D63799071B2069D058E5F42FCEC6804ACCD2C7EA6CF722380F1FF4E5191D7B0385152482E829F3FBB44AA626D59CE609092B8150E610C502B```
6. The following step can be conducted within terminal (e.g., with nano) or can be conducted with the built-in Gnome-Text-Editor
   1.	Edit /etc/grub.d/40_custom and add to the end of the file:
   2. ```set superusers=“<your username>”```
   3. ```password_pbkdf2 <your username> grub.pbkdf2.sha512.10000.095DB0192324CCACC86DB81455C7E45B266FA9570CAFE8FC413A4C756F6666A35CD907EB73BE95D2C469CAA9C8FEB0F278365738B1FD7AB96EDFA15D0442D8D7.2EC836CCB165599D63799071B2069D058E5F42FCEC6804ACCD2C7EA6CF722380F1FF4E5191D7B0385152482E829F3FBB44AA626D59CE609092B8150E610C502B```
   4. ***NOTE: replace ```<your username>``` with your actual username. If this is done incorrectly, you will have to re-image your device
7.	Run:
    1. ```sudo update-grub```
8. Reboot\

***After this reboot, you will be forced to login with your username and GRUB password configured in #4.1 above***

## Onboarding your device
1. Open the Intune Company Portal App
2. Login with your 38North credentials
3. Wait for Company Portal to complete all syncronization actions.
4. Use Edge to access 38North Resources by going to [MyApps](https://myapps.microsoft.com/)
