using System;
using Microsoft.AspNetCore.Builder;

namespace HansKindberg.Web.Authorization.Builder.Extentsions
{
	[CLSCompliant(false)]
	public static class ApplicationBuilderExtension
	{
		#region Methods

		public static IApplicationBuilder UseExtendedAuthorization(this IApplicationBuilder applicationBuilder)
		{
			if(applicationBuilder == null)
				throw new ArgumentNullException(nameof(applicationBuilder));

			applicationBuilder.UseMiddleware<ExtendedAuthorizationMiddleware>();

			applicationBuilder.UseAuthorization();

			return applicationBuilder;
		}

		#endregion
	}
}