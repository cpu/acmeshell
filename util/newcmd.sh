#
# Utility script to create new acmeshell command from template
#

set -e
set -x

USAGE="Usage: $0 <command name>"

if [ $# -eq 0 ]; then
    echo "No command name provided..."
    echo "$USAGE"
    exit 1
fi

# Change to the directory the script is running from
cd "$(dirname "$0")"

CMDS_DIR="../shell/commands"
NEW_PKG="$CMDS_DIR/$1"

# If there is already a package directory in CMDS_DIR with the same name as
# requested, exit
if [ -d "$NEW_PKG" ]
then
   echo "Package $NEW_PKG already exists."
   exit 1
fi

# Make the package directory
mkdir $NEW_PKG

NEW_PKG_FILE="$NEW_PKG/$1.go"

TEMPLATE=$(cat <<-EOM
package CMD_NAME_SUBST

import (
	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "CMD_NAME_SUBST",
			Help:     "TODO: Describe the CMD_NAME_SUBST command",
			LongHelp: "TODO: Describe the CMD_NAME_SUBST command (long)",
			Func:     CMD_NAME_SUBSTHandler,
		},
		nil)
}

// TODO: Implement CMD_NAME_SUBSTHandler
func CMD_NAME_SUBSTHandler(c *ishell.Context) {
	c.Printf("CMD_NAME_SUBST Hello world\n")
}
EOM
)

# Write template to a .go file in the package directory, replacing
# CMD_NAME_SUBST with the name of the cmd.
echo "$TEMPLATE" | sed "s/CMD_NAME_SUBST/$1/g" > "$NEW_PKG_FILE"

# Format the .go
gofmt -s -w "$NEW_PKG_FILE"

echo "Created $NEW_PKG_FILE"

# Add an import of the new package to ../shell/acmeshell.go
sed -i "s/\t\/\/ Import new commands here:/\t\/\/ Import new commands here:\n\t_ \"github.com\/cpu\/acmeshell\/shell\/commands\/$1\"/" "../shell/acmeshell.go"

# And fix the import order
goimports -w "../shell/acmeshell.go"

# Finally open the new .go file for the command in the $EDITOR of choice
$EDITOR $NEW_PKG_FILE
