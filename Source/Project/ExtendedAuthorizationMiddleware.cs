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
					var nameClaimType = context.User.Identities.FirstOrDefault()?.NameClaimType ?? options.NameClaimType;
					var roleClaimType = context.User.Identities.FirstOrDefault()?.RoleClaimType ?? options.RoleClaimType;

					var policy = await this.AuthorizationResolver.GetPolicyAsync(context.User);
					var permissionClaims = policy.Permissions.Select(permission => new Claim(options.PermissionClaimType, permission)).ToArray();
					var roleClaims = policy.Roles.Select(role => new Claim(roleClaimType, role)).ToArray();

					var identity = new ClaimsIdentity(this.GetType().Name, nameClaimType, roleClaimType);
					identity.AddClaims(permissionClaims);
					identity.AddClaims(roleClaims);

					this.Logger.LogDebugIfEnabled($"Adding {permissionClaims.Length} permission-claims and {roleClaims.Length} role-claims to user {context.User.Identity.Name}.");

					context.User.AddIdentity(identity);
				}
			}

			await this.Next(context);
		}

		#endregion
	}
}