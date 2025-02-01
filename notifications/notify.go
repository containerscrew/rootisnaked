package notifications

// For linux native notifications
// func SendNotification(var1, var2 string) error {
// 	title := "Privilege Escalation Detected!"
// 	message := fmt.Sprintf("User ID changed from %d to %d", var1, var2)

// 	return beeep.Alert(title, message, "")
// }

// func SendNotification(var1, var2 string) error {
// 	title := "Privilege Escalation Detected!"
// 	message := fmt.Sprintf("User ID changed from %s to %s", var1, var2)

// 	// Use notify-send (Linux)
// 	cmd := exec.Command("notify-send", title, message)
// 	return cmd.Run()
// }

// TODO: implement this "github.com/getlantern/systray" package

// Windows
// func sendNotification(title, message string) {
// 	notification := toast.Notification{
// 		AppID:   "MyApp",
// 		Title:   title,
// 		Message: message,
// 	}
// 	_ = notification.Push()
// }

// Mac OSX
// func sendNotification(title, message string) {
// 	cmd := exec.Command("osascript", "-e", fmt.Sprintf(`display notification "%s" with title "%s"`, message, title))
// 	err := cmd.Run()
// 	if err != nil {
// 		fmt.Println("Failed to send notification:", err)
// 	}
// }
