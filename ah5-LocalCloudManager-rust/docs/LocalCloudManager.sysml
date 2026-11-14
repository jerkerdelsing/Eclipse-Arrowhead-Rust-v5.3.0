package LocalCloudManagerImplementations {
    doc /* Implementation variability, not a declaration of proven substitution. Java/Go variant descriptions are retained source inventory, not revalidated runtime claims in this Rust acceptance. */
    port def OperatorUIPort;
    port def LocalCloudManagementPort;
    port def SysMonitorPublisherPort;
    port def ProviderClientPort;
    port def RuntimeControlPort;
    part def LocalCloudManagerContract {
        port operatorUI : OperatorUIPort;
        port localCloudManagement : LocalCloudManagementPort;
        port sysMonitor : SysMonitorPublisherPort;
        port providers : ~ProviderClientPort;
        port runtime : ~RuntimeControlPort;
        attribute systemVersion : String = "5.4.0";
        attribute serviceVersion : String = "1.0.0";
    }
    part def JavaCloudManager :> LocalCloudManagerContract {
        attribute sourceLocation : String = "ah5-support-java-spring/LocalCloudManager";
        attribute implementation : String = "Existing Java-cloud Node.js adapter; not Java-language source";
    }
    part def GoCloudManager :> LocalCloudManagerContract {
        attribute sourceLocation : String = "ah5-support-go/LocalCloudManager";
        attribute implementation : String = "Native Go, embedded UI, isolated nested module";
        attribute qualification : String = "Relocated development implementation; Java parity not proven";
        attribute deploymentSnapshot : String = "Arrowhead-test-cloud-go/native-go retained unchanged";
        attribute limitations : String = "Subscription writes no-op; intercloud placeholder; synthetic status; localhost cookie/origin separation incomplete";
    }
    part def RustCloudManager :> LocalCloudManagerContract {
        attribute sourceLocation : String = "ah5-support-rust/LocalCloudManager";
        attribute qualification : String = "Native mTLS system API and HTTPS/password console; pinned certificate-bound provider clients; Java substitution not proven";
        attribute deploymentSnapshot : String = "Arrowhead-test-cloud-rust/candidate-native; old core-systems snapshot unchanged";
        attribute consoleEndpoint : String = "https://127.0.0.1:10590/";
        attribute systemEndpoint : String = "https://127.0.0.1:10520/localcloud/";
        attribute providerAuthentication : String = "Verified local sy certificate plus matching IDENTITY-TOKEN; expected provider CN/profile pinned before login";
        attribute subscriptionControl : String = "Actual SysMonitor writes with If-Match revision checks";
        attribute monitoringTransport : String = "Native AMQP mTLS/EXTERNAL publisher, confirms; broker-backed SysMonitor history and subscriptions";
        attribute federationStatus : String = "Actual native Gatekeeper/GateTunnel relay, negotiated sessions and native RandomDataProducer inter-cloud delivery";
        attribute implementations : String = "Java and Go remain separately identified peers; explicit RustDev=Lab binding, no legacy encryption downgrade";
        attribute runtimeControl : String = "Separate token-authenticated Rust gateway; candidate project/role allowlist; no Docker socket in manager";
        attribute limitations : String = "Onboarding and other support integrations incomplete; in-memory console sessions; exhaustive Java parity, OS advisory clearance, automatic renewal and ISO certification unproven; functional-only producer/historian acceptance, no performance target";
    }
    variation part def SelectedManager :> LocalCloudManagerContract {
        variant javaCloud : JavaCloudManager;
        variant go : GoCloudManager;
        variant rust : RustCloudManager;
    }
}
