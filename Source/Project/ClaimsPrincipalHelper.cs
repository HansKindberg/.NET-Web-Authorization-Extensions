using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.Extensions.Logging;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public class ClaimsPrincipalHelper : IClaimsPrincipalHelper
	{
		#region Fields

		private static readonly IEnumerable<string> _userIdentifierClaimTypes = new[] {ClaimTypes.NameIdentifier, JwtClaimTypes.Subject};
		private static readonly IEnumerable<string> _userPrincipalNameClaimTypes = new[] {ClaimTypes.Upn, "upn"};

		#endregion

		#region Properties

		protected internal virtual IEnumerable<string> UserIdentifierClaimTypes => _userIdentifierClaimTypes;
		protected internal virtual IEnumerable<string> UserPrincipalNameClaimTypes => _userPrincipalNameClaimTypes;

		#endregion

		#region Methods

		protected internal virtual async Task<IEnumerable<Claim>> GetClaimsAsync(ClaimsPrincipal claimsPrincipal, IEnumerable<string> claimTypes, LogLevel logLevel, ILogger logger)
		{
			if(claimsPrincipal == null)
				throw new ArgumentNullException(nameof(claimsPrincipal));

			if(claimTypes == null)
				throw new ArgumentNullException(nameof(claimTypes));

			var claims = new List<Claim>();

			// ReSharper disable All
			foreach(var claimType in claimTypes)
			{
				foreach(var claimsIdentity in claimsPrincipal.Identities.Where(claimsIdentity => claimsIdentity != null))
				{
					foreach(var claim in claimsIdentity.FindAll(claimType))
					{
						claims.Add(claim);
					}
				}
			}
			// ReSharper restore All

			if(claims.Count > 1 && logger != null && logger.IsEnabled(logLevel))
				logger.Log(logLevel, $"Multiple claims were found. The following claims were found: {string.Join(", ", claims.Select(claim => $"{claim.Type}: {claim.Value}"))}");

			return await Task.FromResult(claims);
		}

		public virtual async Task<IEnumerable<Claim>> GetUserIdentifierClaimsAsync(ClaimsPrincipal claimsPrincipal, ILogger logger = null)
		{
			return await this.GetClaimsAsync(claimsPrincipal, this.UserIdentifierClaimTypes, LogLevel.Warning, logger);
		}

		public virtual async Task<IEnumerable<Claim>> GetUserPrincipalNameClaimsAsync(ClaimsPrincipal claimsPrincipal, ILogger logger = null)
		{
			return await this.GetClaimsAsync(claimsPrincipal, this.UserPrincipalNameClaimTypes, LogLevel.Warning, logger);
		}

		#endregion
	}
}