import React, { FunctionComponent, useEffect, useState } from "react";
import { EmptyState, EmptyStateBody, Spinner } from "@patternfly/react-core";
import { ErrorCircleOIcon } from "@patternfly/react-icons";
import { AuthService, UsernameAndPassword, useAuth } from "./useAuth.ts";
import { If } from "../common";
import { BasicAuthModal } from "../modals";

enum AuthState {
    AUTHENTICATING, AUTHENTICATED, AUTHENTICATION_FAILED
}

/**
 * Properties
 */
export type AuthProps = {
    children: React.ReactNode;
};

/**
 * Protect the application with OIDC authentication.
 */
export const ApplicationAuth: FunctionComponent<AuthProps> = (props: AuthProps) => {
    const [authState, setAuthState] = useState<AuthState>(AuthState.AUTHENTICATING);
    const auth: AuthService = useAuth();

    const basicAuthLogin = (creds: UsernameAndPassword): void => {
        console.info("[ApplicationAuth] Using username and password.");
        auth.login(creds.username, creds.password);
        setAuthState(AuthState.AUTHENTICATED);
    };

    useEffect(() => {
        // Guard against state updates after unmount while the async auth bootstrap is still running.
        let isMounted = true;

        const bootstrap = async () => {
            try {
                await auth.login("", "");

                // Mark the app as authenticated only after the session is actually available.
                if (isMounted && await auth.isAuthenticated()) {
                    console.info("[ApplicationAuth] Authentication successful.");
                    setAuthState(AuthState.AUTHENTICATED);
                }
            } catch (error) {
                // TODO display the auth error
                console.error("[ApplicationAuth] Authentication failed: ", error);
                if (isMounted) {
                    setAuthState(AuthState.AUTHENTICATION_FAILED);
                }
            }
        };

        if (auth.isOidcAuthEnabled()) {
            void bootstrap();
        } else if (auth.isBasicAuthEnabled()) {
            // DO NOTHING
        } else {
            setAuthState(AuthState.AUTHENTICATED);
        }

        return () => {
            // Ignore late async completions once the component is gone.
            isMounted = false;
        };
    }, []);

    return (
        <>
            <If condition={authState === AuthState.AUTHENTICATING && auth.isOidcAuthEnabled()}>
                <EmptyState  headingLevel="h4"   titleText="Loading">
                    <EmptyStateBody>
                        <Spinner size="xl" aria-label="Loading spinner" />
                    </EmptyStateBody>
                </EmptyState>
            </If>
            <If condition={authState === AuthState.AUTHENTICATING && auth.isBasicAuthEnabled()}>
                <BasicAuthModal onLogin={basicAuthLogin}></BasicAuthModal>
            </If>
            <If condition={authState === AuthState.AUTHENTICATION_FAILED}>
                <EmptyState  headingLevel="h4" icon={ErrorCircleOIcon}  titleText="Empty state">
                    <EmptyStateBody>
                        Authentication failed.
                    </EmptyStateBody>
                </EmptyState>
            </If>
            <If condition={authState === AuthState.AUTHENTICATED} children={props.children} />
        </>
    );
};
