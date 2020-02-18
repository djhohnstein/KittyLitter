# KittyLitter

This project was made for an upcoming PRCCDC event. It is comprised of two components, `KittyLitter.exe` and `KittyScooper.exe`. This will bind across TCP, SMB, and MailSlot channels to communicate credential material to lowest privilege attackers.

## KittyLitter

The server component of the credential dumper. This will run a modified version of Mimikatz using LogonPasswords, parsing the output and sending it to the three channels. The first client to connect to this channel will receive the material. Must be run as admin. Highly suggest you install as a service or auto-start executable.

## KittyScooper

The client component of the credential dumper. Run this from any client machine and pass the host you wish to retrieve credential material from as the first argument (e.g. `KittyScooper.exe localhost`)

## LAPS

Service executable of KittyLitter.

## Final Notes

This project is purely for fun and chaos.