# .NET-Web-Authorization-Extensions

Additions and extensions for .NET web-authorization (ASP.NET Core).

Includes a variant of https://github.com/PolicyServer/PolicyServer.Local.

[![NuGet](https://img.shields.io/nuget/v/HansKindberg.Web.Authorization.svg?label=NuGet)](https://www.nuget.org/packages/HansKindberg.Web.Authorization)

## Notes

All custom permission-providers and role-providers needs to be registered as a service.

	public virtual void ConfigureServices(IServiceCollection services)
	{
		services.AddSingleton<MyRoleProvider>();
		services.AddSingleton<MyPermissionProvider>();
	}