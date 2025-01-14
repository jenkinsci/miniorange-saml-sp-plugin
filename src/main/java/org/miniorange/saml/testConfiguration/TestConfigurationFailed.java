/*
 * Copyright (c) 2023
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.miniorange.saml.testConfiguration;


import hudson.model.Action;

public class TestConfigurationFailed implements Action {

  private final String errorCode;
  private final String errorMessage;
  private final String resolution;
  private final String certificateExpected;

  public TestConfigurationFailed(String errorCode, String errorMessage, String resolution, String certificateExpected) {
    this.errorCode = errorCode;
    this.errorMessage = errorMessage;
    this.resolution = resolution;
    this.certificateExpected = certificateExpected;
  }

  public String getErrorCode() {
    return errorCode;
  }

  public String getErrorMessage() {
    return errorMessage;
  }

  public String getResolution() {
    return resolution;
  }

  public String getCertificateExpected() {
    return certificateExpected;
  }

  @Override
  public String getIconFileName() {
    return "";
  }

  @Override
  public String getDisplayName() {
    return "testConfigurationFailed";
  }

  @Override
  public String getUrlName() {
    return "/testConfigurationFailed";
  }

}
