MAILTO="robots@prglab.cz"

# Do full VM backups (together with snapshots) every Sunday at 1:30 AM
30 1 * * 0		root		/opt/vcenterbackup/vcb.py --do-snapshots --do-full-backups

# Twice a day create snapshots
30 1,13 * * 1-6		root		/opt/vcenterbackup/vcb.py --do-snapshots
30 13   * * 0			root		/opt/vcenterbackup/vcb.py --do-snapshots

