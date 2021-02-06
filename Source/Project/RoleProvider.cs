using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using HansKindberg.Web.Authorization.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public abstract class RoleProvider : IRoleProvider
	{
		#region Constructors

		protected RoleProvider(IClaimsPrincipalHelper claimsPrincipalHelper, ILoggerFactory loggerFactory, IOptionsMonitor<ExtendedAuthorizationOptions> optionsMonitor)
		{
			this.ClaimsPrincipalHelper = claimsPrincipalHelper ?? throw new ArgumentNullException(nameof(claimsPrincipalHelper));
			this.Logger = (loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory))).CreateLogger(this.GetType());
			this.OptionsMonitor = optionsMonitor ?? throw new ArgumentNullException(nameof(optionsMonitor));
		}

		#endregion

		#region Properties

		protected internal virtual IClaimsPrincipalHelper ClaimsPrincipalHelper { get; }
		protected internal virtual ILogger Logger { get; }
		protected internal virtual IOptionsMonitor<ExtendedAuthorizationOptions> OptionsMonitor { get; }

		#endregion

		#region Methods

		[SuppressMessage("Style", "IDE0066:Convert switch statement to expression")]
		public virtual async Task<IEnumerable<string>> GetRolesAsync(IPrincipal principal)
		{
			// ReSharper disable ConvertSwitchStatementToSwitchExpression
			switch(principal)
			{
				case null:
					throw new ArgumentNullException(nameof(principal));
				case ClaimsPrincipal claimsPrincipal:
					return await this.GetRolesInternalAsync(claimsPrincipal);
				default:
					return Enumerable.Empty<string>();
			}
			// ReSharper restore ConvertSwitchStatementToSwitchExpression
		}

		protected internal virtual async Task<ISet<string>> GetRolesInternalAsync(ClaimsPrincipal claimsPrincipal)
		{
			if(claimsPrincipal == null)
				throw new ArgumentNullException(nameof(claimsPrincipal));

			var roles = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

			// ReSharper disable All
			foreach(var claimsIdentity in claimsPrincipal.Identities.Where(claimsIdentity => claimsIdentity != null))
			{
				if(this.OptionsMonitor.CurrentValue.Roles.ExcludedRoleClaimTypes.Contains(claimsIdentity.RoleClaimType))
					continue;

				foreach(var roleClaim in claimsIdentity.FindAll(claimsIdentity.RoleClaimType))
				{
					if(roleClaim?.Value == null)
						continue;

					roles.Add(roleClaim.Value);
				}
			}
			// ReSharper restore All

			return await Task.FromResult(roles);
		}

		#endregion
	}
}