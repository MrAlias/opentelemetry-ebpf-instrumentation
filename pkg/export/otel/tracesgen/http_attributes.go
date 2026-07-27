// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen // import "go.opentelemetry.io/obi/pkg/export/otel/tracesgen"

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func httpServerTraceAttributes(
	span *request.Span,
	optionalAttrs map[attr.Name]struct{},
	redactSet map[string]struct{},
) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		request.HTTPResponseStatusCode(span.Status),
		request.ClientAddr(request.PeerAsClient(span)),
		request.ServerAddr(request.SpanHost(span)),
		request.ServerPort(span.HostPort),
		request.HTTPRequestBodySize(int(span.RequestBodyLength())),
		request.HTTPResponseBodySize(span.ResponseBodyLength()),
	}
	if span.Method != "" {
		attrs = append(attrs, request.HTTPRequestMethod(span.Method))
	}
	if span.Path != "" {
		attrs = append(attrs, request.HTTPUrlPath(span.Path))
	}
	if scheme := request.HTTPScheme(span); scheme != "" {
		attrs = append(attrs, semconv.URLScheme(scheme))
	}
	if span.Route != "" {
		attrs = append(attrs, semconv.HTTPRoute(span.Route))
	}
	if span.SubType == request.HTTPSubtypeGraphQL && span.GraphQL != nil {
		if _, ok := optionalAttrs[attr.GraphQLDocument]; ok {
			attrs = append(attrs, semconv.GraphQLDocument(span.GraphQL.Document))
		}
		attrs = append(attrs, semconv.GraphQLOperationName(span.GraphQL.OperationName))
		attrs = append(attrs, request.GraphqlOperationType(span.GraphQL.OperationType))
	}
	if _, ok := optionalAttrs[attr.HTTPUrlQuery]; ok {
		if index := strings.IndexByte(span.FullPath, '?'); index >= 0 {
			if query := scrubQuery(span.FullPath[index+1:], redactSet); query != "" {
				attrs = append(attrs, request.HTTPUrlQuery(query))
			}
		}
	}
	return attrs
}
