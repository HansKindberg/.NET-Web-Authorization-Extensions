using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using HansKindberg.Web.Authorization.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.Logging.Extensions;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public class ExtendedAuthorizationMiddleware
	{
		#region Fields

		private static readonly string _permissionsIdentityAuthenticationType = $"{typeof(ExtendedAuthorizationMiddleware).FullName}:Permissions";
		private static readonly string _rolesIdentityAuthenticationType = $"{typeof(ExtendedAuthorizationMiddleware).FullName}:Roles";

		#endregion

		#region Constructors

		public ExtendedAuthorizationMiddleware(IAuthorizationResolver authorizationResolver, ILoggerFactory loggerFactory, RequestDelegate next, IOptionsMonitor<ExtendedAuthorizationOptions> optionsMonitor)
		{
			this.AuthorizationResolver = authorizationResolver ?? throw new ArgumentNullException(nameof(authorizationResolver));
			this.Logger = (loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory))).CreateLogger(this.GetType());
			this.Next = next ?? throw new ArgumentNullException(nameof(next));
			this.OptionsMonitor = optionsMonitor ?? throw new ArgumentNullException(nameof(optionsMonitor));
		}

		#endregion

		#region Properties

		protected internal virtual IAuthorizationResolver AuthorizationResolver { get; }
		protected internal virtual ILogger Logger { get; }

		[SuppressMessage("Naming", "CA1716:Identifiers should not match keywords")]
		protected internal virtual RequestDelegate Next { get; }

		protected internal virtual IOptionsMonitor<ExtendedAuthorizationOptions> OptionsMonitor { get; }
		protected internal virtual string PermissionsIdentityAuthenticationType => _permissionsIdentityAuthenticationType;
		protected internal virtual string RolesIdentityAuthenticationType => _rolesIdentityAuthenticationType;

		#endregion

		#region Methods

		public virtual async Task Invoke(HttpContext context)
		{
			if(context == null)
				throw new ArgumentNullException(nameof(context));

			var options = this.OptionsMonitor.CurrentValue;

			this.Logger.LogDebugIfEnabled($"{this.GetType().Name} is{(options.MiddlewareEnabled ? null : " not")} enabled.");

			if(options.MiddlewareEnabled)
			{
				if(context.User.Identity != null && context.User.Identity.IsAuthenticated)
				{
					const string alreadyAddedLogFormat = "{0} already added. Probably because an ITicketStore, using memory-cache, is configured for the cookie-authentication.";
					var containsPermissions = context.User.Identities.Any(item => string.Equals(item.AuthenticationType, this.PermissionsIdentityAuthenticationType, StringComparison.OrdinalIgnoreCase));
					var containsRoles = context.User.Identities.Any(item => string.Equals(item.AuthenticationType, this.RolesIdentityAuthenticationType, StringComparison.OrdinalIgnoreCase));

					if(containsPermissions)
						this.Logger.LogDebugIfEnabled(string.Format(null, alreadyAddedLogFormat, "Permissions"));

					if(containsRoles)
						this.Logger.LogDebugIfEnabled(string.Format(null, alreadyAddedLogFormat, "Roles"));

					if(!containsPermissions || !containsRoles)
					{
						var nameClaimType = context.User.Identities.FirstOrDefault()?.NameClaimType ?? options.NameClaimType;
						var roleClaimType = context.User.Identities.FirstOrDefault()?.RoleClaimType ?? options.RoleClaimType;

						var policy = await this.AuthorizationResolver.GetPolicyAsync(context.User);

						if(!containsPermissions)
						{
							var permissionClaims = policy.Permissions.Select(permission => new Claim(options.PermissionClaimType, permission)).ToArray();

							this.Logger.LogDebugIfEnabled($"Adding {permissionClaims.Length} permission-claims to user {context.User.Identity.Name}.");

							var identity = new ClaimsIdentity(this.PermissionsIdentityAuthenticationType, nameClaimType, roleClaimType);
							identity.AddClaims(permissionClaims);
							context.User.AddIdentity(identity);
						}

						if(!containsRoles)
						{
							var roleClaims = policy.Roles.Select(role => new Claim(roleClaimType, role)).ToArray();

							this.Logger.LogDebugIfEnabled($"Adding {roleClaims.Length} role-claims to user {context.User.Identity.Name}.");

							var identity = new ClaimsIdentity(this.RolesIdentityAuthenticationType, nameClaimType, roleClaimType);
							identity.AddClaims(roleClaims);
							context.User.AddIdentity(identity);
						}
					}
				}
			}

			await this.Next(context);
		}

		#endregion
	}
}