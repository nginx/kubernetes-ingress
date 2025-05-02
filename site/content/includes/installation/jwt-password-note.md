---
docs: 
---

{{< note >}} For security, follow these practices with JSON Web Tokens (JWTs), passwords, and shell history:

1. **JWTs:** JWTs are sensitive information. Store them securely. Delete them after use to prevent unauthorized access.

1. **Shell history:** Commands that include JWTs or passwords are recorded in the history of your shell, in plain text. Clear your shell history after running such commands. For example, if you use bash, you can delete commands in your `~/.bash_history` file. Alternatively, you can run the `history -c` command to erase your shell history.

Follow these practices to help ensure the security of your system and data. {{< /note >}}
