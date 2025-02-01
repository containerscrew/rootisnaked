package notifications

import (
	"log"
	"os/exec"
)

func SendNotification(title, message string) {
	cmd := exec.Command("notify-send tete tete")
	err := cmd.Run()
	if err != nil {
		log.Print("Failed to send notification:", err)
	}
}

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
