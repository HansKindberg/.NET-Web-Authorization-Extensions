using System;
using System.Runtime.InteropServices;
using HansKindberg.Web.Authorization.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HansKindberg.Web.Authorization.DependencyInjection.Extensions
{
	[CLSCompliant(false)]
	public static class ServiceCollectionExtension
	{
		#region Methods

		public static IServiceCollection AddExtendedAuthorization(this IServiceCollection services, IConfiguration configuration, string configurationSectionName = nameof(Microsoft.AspNetCore.Authorization))
		{
			if(services == null)
				throw new ArgumentNullException(nameof(services));

			if(configuration == null)
				throw new ArgumentNullException(nameof(configuration));

			var configurationSection = configuration.GetSection(configurationSectionName);

			services.Configure<AuthorizationOptions>(configurationSection);

			services.Configure<ExtendedAuthorizationOptions>(configurationSection);

			services
				.AddSingleton<IAuthorizationResolver, AuthorizationResolver>()
				.AddSingleton<IClaimsPrincipalHelper, ClaimsPrincipalHelper>()

				//Services.AddAuthorization();
				//.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
				.AddTransient<IAuthorizationPolicyProvider, AuthorizationPolicyProvider>()
				.AddTransient<IAuthorizationHandler, PermissionHandler>()
				.AddPermissionProviders()
				.AddRoleProviders();

			services.AddAuthorization();

			services.AddMemoryCache();

			return services;
		}

		public static IServiceCollection AddPermissionProviders(this IServiceCollection services)
		{
			if(services == null)
				throw new ArgumentNullException(nameof(services));

			services.AddSingleton<ConfigurationPermissionProvider>();

			return services;
		}

		public static IServiceCollection AddRoleProviders(this IServiceCollection services)
		{
			if(services == null)
				throw new ArgumentNullException(nameof(services));

			services.AddSingleton<ConfigurationRoleProvider>();
			if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				services.AddSingleton<WindowsRoleProvider>();

			return services;
		}

		#endregion
	}
}