using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public interface IClaimsPrincipalHelper
	{
		#region Methods

		Task<IEnumerable<Claim>> GetUserIdentifierClaimsAsync(ClaimsPrincipal claimsPrincipal, ILogger logger = null);
		Task<IEnumerable<Claim>> GetUserPrincipalNameClaimsAsync(ClaimsPrincipal claimsPrincipal, ILogger logger = null);

		#endregion
	}
}