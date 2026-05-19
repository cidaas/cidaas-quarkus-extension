package de.cidaas.quarkus.extension.deployment;

import de.cidaas.quarkus.extension.address.validation.AddressValidationRequest;
import de.cidaas.quarkus.extension.address.validation.AddressValidationResult;
import de.cidaas.quarkus.extension.address.validation.AddressValidationService;
import de.cidaas.quarkus.extension.annotation.GroupAllowed;
import de.cidaas.quarkus.extension.annotation.PatValidation;
import de.cidaas.quarkus.extension.annotation.TokenValidation;
import de.cidaas.quarkus.extension.runtime.AuthFilter;
import de.cidaas.quarkus.extension.runtime.PatAuthFilter;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.resteasy.reactive.spi.CustomContainerRequestFilterBuildItem;

class CidaasQuarkusExtensionProcessor {

    private static final String FEATURE = "cidaas-quarkus-extension";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }
    
    @BuildStep
    CustomContainerRequestFilterBuildItem registerAuthFilter() {
        return new CustomContainerRequestFilterBuildItem(AuthFilter.class.getName());
    }

    @BuildStep
    CustomContainerRequestFilterBuildItem registerPatAuthFilter() {
        return new CustomContainerRequestFilterBuildItem(PatAuthFilter.class.getName());
    }
    
    @BuildStep
    AdditionalBeanBuildItem registerAdditonalBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(TokenValidation.class, PatValidation.class, GroupAllowed.class,
                        AddressValidationService.class, AddressValidationRequest.class, AddressValidationResult.class)
                .build();
    }
}
