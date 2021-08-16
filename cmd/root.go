package cmd

import (
	"fmt"
	"genrsa/pkg/generate"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "genrsa",
	Short: "Generate RSA private Key & public Key",
	Long:  `Easy RSA priv & pub file generation from CLI`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pvKeyFile, pbKeyFile, err := generate.Create()
		if err != nil {
			return err
		}

		println("Files Generated")
		println(fmt.Sprintf("Private Key File: %s", pvKeyFile.Name()))
		println(fmt.Sprintf("Public Key File: %s", pbKeyFile.Name()))
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.genrsa.yaml)")

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func initConfig() {
	if cfgFile != "" {

		viper.SetConfigFile(cfgFile)

	} else {

		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".genrsa")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
