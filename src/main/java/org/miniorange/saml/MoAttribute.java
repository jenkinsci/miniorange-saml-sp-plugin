package org.miniorange.saml;

import hudson.Extension;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.Objects;

public class MoAttribute extends MoAttributeEntry{
    /**
     * Name of the attribute in the SAML Response.
     */
    private final String name;
    /**
     * Name to display as attribute's value label on the user profile.
     */
    private final String displayName;

    @DataBoundConstructor
    public MoAttribute(String name, String displayName) {
        this.name = name;
        this.displayName = displayName;
    }

    public String getName() {
        return name;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<MoAttributeEntry> {
        @Override
        public String getDisplayName() {
            return "SAML Attribute";
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MoAttribute attribute = (MoAttribute) o;
        return Objects.equals(name, attribute.name) &&
                Objects.equals(displayName, attribute.displayName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, displayName);
    }
}
