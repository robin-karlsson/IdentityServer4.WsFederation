using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace IdentityServer4.WsFederation.Behavior
{
    public static class ServiceCollectionExtensions
    {
        public static void AddWsFederationRedirectSupport(this IServiceCollection services)
        {
            services.Replace(ServiceDescriptor.Transient<IEndSessionRequestValidator, WsFederationRedirectEndSessionRequestValidator>());
            services.TryAddTransient<EndSessionRequestValidator, EndSessionRequestValidator>();
        }

        public static void AddProviderSelectionAsFallback(this IServiceCollection services)
        {
            services.Replace(ServiceDescriptor.Scoped<AuthenticationService, AuthenticationServiceWithFallback>());
        }
    }
}