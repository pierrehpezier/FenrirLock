package utils

import (
	_ "embed"
)

/*
//go:embed update_screen.png
var fake_screen []byte
*/

func ShowFakeScreen() {
	/*
		screenWidth := 800
		screenHeight := 600
		rl.InitWindow(screenWidth, screenHeight, "Embedded Image Viewer")
		rl.ToggleFullscreen()
		defer rl.CloseWindow()

		// Load image from byte array
		img, err := loadImageFromBytes(myimage_png)
		if err != nil {
			log.Fatalf("Failed to load image: %v", err)
		}

		// Convert Image to Texture
		texture := rl.LoadTextureFromImage(img)
		rl.UnloadImage(img) // Free the Image from RAM after creating the texture

		rl.SetTargetFPS(60)

		// Main loop
		for !rl.WindowShouldClose() {
			rl.BeginDrawing()
			rl.ClearBackground(rl.Black)
			rl.DrawTexture(texture, 0, 0, rl.White) // Draw image at (0,0)
			rl.EndDrawing()
		}

		// Cleanup
		rl.UnloadTexture(texture)
	*/
}
