// Your own rules go next to the packs. A forbid always wins over a permit.

@id("no-network-tools-in-production")
@reason("curl and wget are not allowed in production.")
forbid (principal, action, resource)
when { context.config.environment == "production" &&
       (context.n.commands.contains("curl") || context.n.commands.contains("wget")) };
