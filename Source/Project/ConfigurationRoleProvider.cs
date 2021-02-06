using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using HansKindberg.Web.Authorization.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.Logging.Extensions;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public class ConfigurationRoleProvider : RoleProvider
	{
		#region Constructors

		public ConfigurationRoleProvider(IClaimsPrincipalHelper claimsPrincipalHelper, ILoggerFactory loggerFactory, IOptionsMonitor<ExtendedAuthorizationOptions> optionsMonitor) : base(claimsPrincipalHelper, loggerFactory, optionsMonitor) { }

		#endregion

		#region Methods

		[SuppressMessage("Maintainability", "CA1508:Avoid dead conditional code")]
		protected internal override async Task<ISet<string>> GetRolesInternalAsync(ClaimsPrincipal claimsPrincipal)
		{
			if(claimsPrincipal == null)
				throw new ArgumentNullException(nameof(claimsPrincipal));

			var roles = await base.GetRolesInternalAsync(claimsPrincipal);

			var userIdentifierClaims = (await this.ClaimsPrincipalHelper.GetUserIdentifierClaimsAsync(claimsPrincipal, this.Logger)).ToArray();

			// ReSharper disable All
			if(userIdentifierClaims.Any())
			{
				foreach(var userIdentifierClaim in userIdentifierClaims)
				{
					var userIdentifier = userIdentifierClaim.Value;

					if(userIdentifier == null)
					{
						this.Logger.LogWarningIfEnabled($"The user-identifier value for claim with claim-type \"{userIdentifierClaim.Type}\" is null. The user-identifier is ignored.");

						continue;
					}

					if(string.IsNullOrWhiteSpace(userIdentifier))
					{
						this.Logger.LogWarningIfEnabled($"The user-identifier value, \"{userIdentifier}\", for claim with claim-type \"{userIdentifierClaim.Type}\" is invalid. The user-identifier is ignored.");

						continue;
					}

					foreach(var role in this.OptionsMonitor.CurrentValue.Policy.Roles)
					{
						if(role.Users.Contains(userIdentifier))
							roles.Add(role.Name);
					}
				}
			}
			// ReSharper restore All

			return roles;
		}

		#endregion
	}
}