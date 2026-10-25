#pragma once

// Presence link: while the game is connected to a server, keeps a TCP
// connection to <joined host>:<port> and applies the messages it receives.
namespace presence_link {

// Supervisor loop; never returns. Runs session timeouts too.
void run();

} // namespace presence_link
