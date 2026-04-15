/*
Copyright © 2026 RBProxy
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var activismCmd = &cobra.Command{
	Use:   "activism",
	Short: "Support information for victims of the Israel-Palestine conflict",
	Long:  `Provides a list of international organizations and humanitarian aid groups working to help civilians affected by the conflict.`,
	Run: func(cmd *cobra.Command, args []string) {
		showSupportInfo()
	},
}

func showSupportInfo() {
	fmt.Println(`
============================================================
       HUMANITARIAN SUPPORT: ISRAEL-PALESTINE CONFLICT
============================================================

The following organizations provide neutral medical aid, 
food, and shelter to civilians affected by the ongoing 
hostilities.

1. International Committee of the Red Cross (ICRC)
   Description: Provides emergency medical services and 
   seeks to ensure protection for civilians.
   Link: https://www.icrc.org/

2. Doctors Without Borders (MSF)
   Description: Delivers urgent medical care and surgical 
   support in affected areas.
   Link: https://www.msf.org/

3. UNRWA (United Nations Relief and Works Agency)
   Description: Specialized in providing food and healthcare 
   specifically to Palestinian refugees.
   Link: https://www.unrwa.org/

4. Magen David Adom (MDA)
   Description: Israel's national emergency medical, 
   disaster, ambulance and blood bank service.
   Link: https://www.mdais.org/en

5. Save the Children
   Description: Focuses on the protection and psychological 
   support of children on both sides of the conflict.
   Link: https://www.savethechildren.net/

------------------------------------------------------------
Note: Always verify the organization's transparency and 
current status before making any donations.
============================================================
`)
}

func init() {
	rootCmd.AddCommand(activismCmd)
}
