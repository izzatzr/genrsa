package cmd

import (
	"fmt"
	"genrsa/pkg/generate"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	removeOnExit bool
	RSAKey       generate.Opts
)

var rootCmd = &cobra.Command{
	Use:   "genrsa",
	Short: "Generate RSA private Key & public Key",
	Long:  `Easy RSA priv & pub file generation from CLI`,
	RunE: func(cmd *cobra.Command, args []string) error {

		err := RSAKey.Create()
		if err != nil {
			return err
		}

		println("Files Generated")
		println(fmt.Sprintf("Private Key File: %s", RSAKey.PrivateKey.Path))
		println(fmt.Sprintf("Public Key File: %s", RSAKey.PublicKey.Path))

		if removeOnExit {
			defer os.Remove(RSAKey.PrivateKey.Blob.File.Name())
			defer os.Remove(RSAKey.PublicKey.Blob.File.Name())
		}

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

	rootCmd.Flags().StringVarP(&RSAKey.PrivateKey.Path, "privateKey", "v", "", "path to store private key file (default is store on OS temp dir")
	rootCmd.Flags().StringVarP(&RSAKey.PublicKey.Path, "pb", "b", "", "path to store public key file (default is store on OS temp dir")
	rootCmd.Flags().IntVarP(&RSAKey.PrivateKey.BitSize, "BitSize", "t", 4096, "bitsize")
	rootCmd.Flags().BoolVarP(&removeOnExit, "removeOnExit", "d", false, "remove on exit")
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
