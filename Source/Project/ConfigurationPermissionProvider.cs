using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using HansKindberg.Web.Authorization.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public class ConfigurationPermissionProvider : PermissionProvider
	{
		#region Constructors

		public ConfigurationPermissionProvider(IClaimsPrincipalHelper claimsPrincipalHelper, ILoggerFactory loggerFactory, IOptionsMonitor<ExtendedAuthorizationOptions> optionsMonitor) : base(claimsPrincipalHelper, loggerFactory)
		{
			this.OptionsMonitor = optionsMonitor ?? throw new ArgumentNullException(nameof(optionsMonitor));
		}

		#endregion

		#region Properties

		protected internal virtual IOptionsMonitor<ExtendedAuthorizationOptions> OptionsMonitor { get; }

		#endregion

		#region Methods

		protected internal override async Task<ISet<string>> GetPermissionsInternalAsync(ClaimsPrincipal claimsPrincipal, IEnumerable<string> roles)
		{
			if(claimsPrincipal == null)
				throw new ArgumentNullException(nameof(claimsPrincipal));

			roles ??= Enumerable.Empty<string>();

			var permissions = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

			foreach(var permission in this.OptionsMonitor.CurrentValue.Policy.Permissions)
			{
				if(permission.Roles.Any(role => roles.Contains(role)))
					permissions.Add(permission.Name);
			}

			return await Task.FromResult(permissions);
		}

		#endregion
	}
}